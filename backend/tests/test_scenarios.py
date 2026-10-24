"""Tests for Scenarios S1-S6, Scenario API, WebSocket stream, and idempotence per SPEC §10, §11."""

import json
from fastapi.testclient import TestClient
import pytest

from app.main import app
from app.models import Decision, Tier
from app.scenarios.runner import get_latest_s5_series
from app.scenarios.s1_pdf_hijack import run_s1
from app.scenarios.s2_rug_pull import run_s2
from app.scenarios.s3_stolen_token import run_s3
from app.scenarios.s4_agent_chain import run_s4
from app.scenarios.s5_slow_drift import run_s5
from app.scenarios.s6_legitimate_change import run_s6
from app.store import get_store


def test_scenario_s1_pdf_hijack():
    """S1: Indirect prompt injection via acme_quote.pdf exfiltrates to sinkhole; real world untouched."""
    res = run_s1(reset=True, step_delay_ms=0)
    assert res.passed is True
    assert res.id == "s1"
    # Check pre-attack steps (1: products.csv, 2: price.compare, 3: acme read) must each stay < 15
    for s in res.steps[:3]:
        assert s.defender_view["risk"] < 15, f"Pre-attack step {s.step_number} ({s.tool}) risk={s.defender_view['risk']} >= 15"

    store = get_store()
    alerts = store.list_alerts()
    assert len(alerts) >= 1
    receipt = alerts[-1].receipt
    assert receipt is not None
    assert receipt.root_cause is not None
    assert "acme_quote.pdf" in receipt.root_cause.source

    # Check upload's top contributors: D5 (decoy/watermark), D4 (taint_flow), D1 (contract) — not D2 novelty
    contributions_by_share = sorted(receipt.contributions, key=lambda c: c.share_pct, reverse=True)
    top_3_detectors = [c.detector for c in contributions_by_share[:3]]
    assert set(top_3_detectors) == {"decoy", "taint_flow", "contract"}
    novelty_contrib = next((c for c in receipt.contributions if c.detector == "novelty"), None)
    assert novelty_contrib is None or novelty_contrib.share_pct < 5.0

    captures = store.list_sinkhole_captures()
    assert len(captures) >= 1
    assert any(c.destination == "files-share.xyz" for c in captures)
    assert store.get_egress_logs() == []


def test_scenario_s2_rug_pull():
    """S2: Tampered tool description trips D9; currency.convert disabled for all agents; subsequent call blocked."""
    res = run_s2(reset=True, step_delay_ms=0)
    assert res.passed is True
    assert res.id == "s2"

    store = get_store()
    assert store.is_tool_disabled("currency.convert") is True


def test_scenario_s3_stolen_token():
    """S3: Token replay from new environment without sigil caught on first call; purchase requests untouched."""
    res = run_s3(reset=True, step_delay_ms=0)
    assert res.passed is True
    assert res.id == "s3"

    store = get_store()
    assert store.get_purchase_requests() == []


def test_scenario_s4_agent_chain():
    """S4: Email triage delegates to finance; finance session inherits taint; payment held with ASI07."""
    res = run_s4(reset=True, step_delay_ms=0)
    assert res.passed is True
    assert res.id == "s4"
    assert len(res.steps) == 3

    store = get_store()
    assert store.get_payments() == []

    alerts = store.list_alerts()
    finance_alerts = [a for a in alerts if a.agent_id == "finance-agent"]
    assert len(finance_alerts) >= 1
    receipt = finance_alerts[0].receipt
    assert receipt is not None
    assert "OWASP:ASI07" in receipt.tags
    assert receipt.root_cause is not None
    assert "msg_1042" in receipt.root_cause.source


def test_scenario_s5_slow_drift():
    """S5: CUSUM raises sustained alarm (>=3 days) between day 10 and 25; EWMA never sustains alarm."""
    from app.detectors.d6_drift_cusum import get_cusum_tracker

    res = run_s5(reset=True, step_delay_ms=0)
    assert res.id == "s5"
    assert res.passed is True

    tracker = get_cusum_tracker("procurement-agent")
    assert tracker.h == pytest.approx(10 * tracker.kappa)  # h = 5·std, κ = 0.5·std from the same fit
    assert (tracker.mu0, tracker.kappa, tracker.h) != (0.01, 0.01, 0.20)  # the old hand-set values

    series = get_latest_s5_series()
    assert len(series) == 30
    alarm_days = [e["day"] for e in series if e["cusum_alarm"]]
    assert alarm_days, "CUSUM never alarmed on a 30-day +3%/day drift"
    first_alarm = alarm_days[0]
    # Before D6 alarms, no event reaches WATCH from the per-event detectors alone
    assert all(e["max_event_risk_without_d6"] < 30 for e in series if e["day"] < first_alarm)
    # The rolling baseline adapts: it never sustains an alarm the way CUSUM does
    assert sum(e["ewma_alarm"] for e in series) < len(alarm_days)


def test_scenario_s6_legitimate_change():
    """S6: Unapproved quote.request triggers alert; signed contract v2 allows tool cleanly with risk < 30."""
    res = run_s6(reset=True, step_delay_ms=0)
    assert res.passed is True
    assert res.id == "s6"
    assert len(res.steps) == 4


def test_scenario_s1_idempotence_and_reset():
    """Task 0.f: Running S1 twice with reset produces identical receipts (except ids and timestamps)."""
    res1 = run_s1(reset=True, step_delay_ms=0, seed=42)
    store = get_store()
    alert1 = store.list_alerts()[0]
    receipt1 = alert1.receipt

    res2 = run_s1(reset=True, step_delay_ms=0, seed=42)
    store = get_store()
    alert2 = store.list_alerts()[0]
    receipt2 = alert2.receipt

    assert receipt1 is not None and receipt2 is not None
    assert receipt1.risk == receipt2.risk
    assert receipt1.tier == receipt2.tier
    assert receipt1.headline == receipt2.headline
    assert receipt1.headline_short == receipt2.headline_short
    assert receipt1.contract_clause == receipt2.contract_clause
    assert receipt1.tags == receipt2.tags
    assert receipt1.root_cause.source == receipt2.root_cause.source
    assert len(receipt1.contributions) == len(receipt2.contributions)
    for c1, c2 in zip(receipt1.contributions, receipt2.contributions):
        assert c1.detector == c2.detector
        assert c1.score == c2.score
        assert c1.share_pct == c2.share_pct


def test_scenario_api_endpoints():
    """Verify Scenario API endpoints: GET /v1/scenarios, POST run, GET s5 series, and world state."""
    with TestClient(app) as client:
        # GET /v1/scenarios
        r_list = client.get("/v1/scenarios")
        assert r_list.status_code == 200
        data = r_list.json()
        assert len(data) == 7
        assert "s1" in {s["id"] for s in data}
        assert "s6" in {s["id"] for s in data}
        assert "s1l" in {s["id"] for s in data}

        # GET /v1/world/state
        r_world = client.get("/v1/world/state")
        assert r_world.status_code == 200
        w_state = r_world.json()
        assert "purchase_requests" in w_state
        assert "payments" in w_state
        assert "egress_log" in w_state
        assert "delegations" in w_state

        # GET /v1/scenarios/s5/series
        run_s5(reset=True, step_delay_ms=0)
        r_series = client.get("/v1/scenarios/s5/series")
        assert r_series.status_code == 200
        assert len(r_series.json()) == 30


def test_websocket_stream_s1():
    """Task 4: Running S1 produces event, alert and sinkhole messages over WS /v1/stream."""
    with TestClient(app) as client:
        with client.websocket_connect("/v1/stream") as ws:
            # Run S1 synchronously in this test thread
            res = run_s1(reset=True, step_delay_ms=0)
            assert res.passed is True

            # Drain messages from websocket
            received_types: set[str] = set()
            while True:
                try:
                    # Non-blocking or short wait to receive broadcasted messages
                    raw = ws.receive_text()
                    msg = json.loads(raw)
                    msg_type = msg.get("type")
                    if msg_type:
                        received_types.add(msg_type)
                    if msg_type == "scenario_done":
                        break
                except Exception:
                    break

            assert "event" in received_types
            assert "alert" in received_types
            assert "sinkhole" in received_types


def test_evaluation_harness_output_structure():
    """Prompt 4b Task 3: Test evaluation harness with minimal params and verify output structure."""
    from app.eval.run_eval import EvalHarness, format_markdown_table

    harness = EvalHarness(benign_count=3, variants_per_family=1)
    results = harness.run()

    assert results["benchmark"] == "Doppel Agent Defense Evaluation"
    assert results["environment"] == "measured on the Doppel simulator"
    assert "benign" in results
    assert results["benign"]["total_benign_sessions"] == 9
    assert "attacks" in results
    assert results["attacks"]["overall_variants_tested"] == 6
    assert results["attacks"]["overall_detection_rate_pct"] == 100.0
    assert results["attacks"]["real_bytes_leaked"] == 0
    assert "latency_ms" in results
    assert results["latency_ms"]["p50"] >= 0.0

    table = format_markdown_table(results)
    assert "Doppel Security Gateway — Benchmark Results" in table
    assert "measured on the Doppel simulator" in table


def test_meta_endpoint():
    """Prompt 4b Task 5: GET /v1/meta returns version, mode, scenarios, and live_recording."""
    with TestClient(app) as client:
        r = client.get("/v1/meta")
        assert r.status_code == 200
        data = r.json()
        assert data["version"] == "0.1.0"
        assert "mode" in data
        assert "s1" in data["scenarios_available"]
        assert "s6" in data["scenarios_available"]
        assert "live_recording" in data


def test_recordings_never_contain_a_sigil_value():
    """Live transcripts are committed for the hosted demo: no SGL- value may appear anywhere in them."""
    import re
    from app.scenarios.s1l_replay import RECORDINGS_DIR

    for path in RECORDINGS_DIR.glob("*.json"):
        assert not re.search(r"SGL-[0-9A-Fa-f]{8}", path.read_text(encoding="utf-8")), path.name


def test_s1l_scenario_without_recording():
    """Prompt 4b Task 2: When no recording exists, S1L reports unavailable."""
    from app.scenarios.s1l_replay import run_s1l

    res = run_s1l()
    # If no recording exists, it cleanly returns unavailable
    if not res.steps:
        assert res.id == "s1l"
        assert res.passed is False
        assert "unavailable" in res.summary.lower()

