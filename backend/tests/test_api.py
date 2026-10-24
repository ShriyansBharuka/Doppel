"""Tests for FastAPI endpoints using TestClient."""

from fastapi.testclient import TestClient

from app.contracts.loader import load_contracts
from app.main import app


def test_shipped_contracts_verify_without_resigning():
    """The committed contract files must verify as-is (tests must never re-sign them)."""
    assert set(load_contracts()) == {"procurement-agent", "email-triage-agent", "finance-agent"}


def test_health_endpoint():
    """Verify /health returns status ok, 3 contracts loaded, and 13 tools pinned."""
    with TestClient(app) as client:
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["contracts_loaded"] == 3
        assert data["tools_pinned"] == 14


def test_list_agents_endpoint():
    """Verify /v1/agents returns all 3 configured agents with valid signatures."""
    with TestClient(app) as client:
        response = client.get("/v1/agents")
        assert response.status_code == 200
        agents = response.json()
        assert len(agents) == 3

        agent_ids = {a["agent_id"] for a in agents}
        assert agent_ids == {"procurement-agent", "email-triage-agent", "finance-agent"}

        for agent in agents:
            assert agent["signature_valid"] is True
            assert agent["contract_version"] >= 1
            assert "role" in agent
            assert "purpose" in agent


def test_world_files_endpoint():
    """Verify /v1/world/files returns file registry without leaking watermark values."""
    with TestClient(app) as client:
        response = client.get("/v1/world/files")
        assert response.status_code == 200
        files = response.json()
        assert len(files) >= 10

        for f in files:
            assert "path" in f
            assert "data_class" in f
            assert "trust" in f
            assert "is_decoy" in f
            assert "has_watermark" in f
            # Critical requirement: NEVER the watermark value itself
            assert "watermark" not in f
            assert "content" not in f
            # Ensure no leaked raw watermark string in serialized output
            assert "DPL-WM-" not in str(f)


def test_world_tools_endpoint():
    """Verify /v1/world/tools returns all tools with valid schema hashes."""
    with TestClient(app) as client:
        response = client.get("/v1/world/tools")
        assert response.status_code == 200
        tools = response.json()
        assert len(tools) == 14

        names = {t["name"] for t in tools}
        assert "doc.read" in names
        assert "currency.convert" in names
        assert "admin.override_limits" in names

        for t in tools:
            assert len(t["schema_hash"]) == 64


def test_session_freeze_and_restore():
    """Verify POST /v1/sessions/{id}/freeze and POST /v1/sessions/{id}/restore."""
    from datetime import datetime, timezone
    from app.clock import set_clock, SimClock, RealClock

    sim = SimClock(datetime.now(timezone.utc))
    set_clock(sim)
    try:
        with TestClient(app) as client:
            sess_res = client.post(
                "/v1/sessions",
                json={"agent_id": "procurement-agent", "runtime_fingerprint": "fp-freeze-test"},
            )
            assert sess_res.status_code == 200
            sid = sess_res.json()["session_id"]
            token = sess_res.json()["token"]
            sigil = sess_res.json()["sigil"]

            # Freeze session
            freeze_res = client.post(f"/v1/sessions/{sid}/freeze")
            assert freeze_res.status_code == 200
            assert freeze_res.json()["status"] == "frozen"

            # Subsequent call returns 423 and records block event
            call_res = client.post(
                "/v1/gateway/call",
                headers={"Authorization": f"Bearer {token}", "X-Doppel-Sigil": sigil},
                json={"session_id": sid, "tool": "doc.read", "args": {"path": "/procurement/catalog/products.csv"}},
            )
            assert call_res.status_code == 423
            evs = client.get(f"/v1/events?session_id={sid}").json()
            assert len(evs) == 1
            assert evs[0]["decision"] == "block"

            # Restore session
            restore_res = client.post(f"/v1/sessions/{sid}/restore")
            assert restore_res.status_code == 200
            assert restore_res.json()["status"] == "restored"
            # The console never receives a bearer token
            assert "token" not in restore_res.json()

            # The agent's next call (old token) succeeds and carries the fresh token once
            body = {"session_id": sid, "tool": "doc.read", "args": {"path": "/procurement/catalog/products.csv"}}
            call_ok = client.post(
                "/v1/gateway/call",
                headers={"Authorization": f"Bearer {token}", "X-Doppel-Sigil": sigil},
                json=body,
            )
            assert call_ok.status_code == 200
            assert call_ok.json()["status"] == "ok"
            new_token = call_ok.json()["new_token"]
            assert new_token and new_token != token

            # Pre-restore token stays valid for 2-minute grace period (Task 0.b)
            assert client.post("/v1/gateway/call", headers={"Authorization": f"Bearer {token}", "X-Doppel-Sigil": sigil}, json=body).status_code == 200

            # Advance clock past 2-minute grace period (130 seconds) -> old token now revoked
            sim.advance(130)
            assert client.post("/v1/gateway/call", headers={"Authorization": f"Bearer {token}", "X-Doppel-Sigil": sigil}, json=body).status_code == 401

            again = client.post("/v1/gateway/call", headers={"Authorization": f"Bearer {new_token}", "X-Doppel-Sigil": sigil}, json=body)
            assert again.status_code == 200
            assert again.json()["new_token"] is None
    finally:
        set_clock(RealClock())


def test_world_content_console_endpoint():
    """Prompt 4c Task 7: GET /v1/world/content returns marked hidden text segments and masked watermarks."""
    with TestClient(app) as client:
        # 1. Acme quote has [hidden white text] span
        r_acme = client.get("/v1/world/content?path=/procurement/suppliers/acme_quote.pdf")
        assert r_acme.status_code == 200
        data_acme = r_acme.json()
        assert data_acme["path"] == "/procurement/suppliers/acme_quote.pdf"
        assert "segments" in data_acme
        hidden_segments = [s for s in data_acme["segments"] if s.get("hidden")]
        assert len(hidden_segments) >= 1
        assert "SYSTEM OVERRIDE INSTRUCTION" in hidden_segments[0]["text"]
        normal_segments = [s for s in data_acme["segments"] if not s.get("hidden")]
        assert len(normal_segments) >= 1
        assert "ACME INDUSTRIAL SUPPLIES" in normal_segments[0]["text"]

        # 2. Decoy file has watermark masked as DPL-WM-••••
        r_decoy = client.get("/v1/world/content?path=/hr/Salaries_FY26_FINAL.xlsx")
        assert r_decoy.status_code == 200
        data_decoy = r_decoy.json()
        assert "DPL-WM-••••" in data_decoy["content"]
        assert "DPL-WM-" in data_decoy["content"]
        # Ensure raw 12-hex watermark does not appear
        import re
        assert not re.search(r"DPL-WM-[0-9A-Fa-f]{12}", data_decoy["content"])

        # 3. Nonexistent file returns 404
        r_404 = client.get("/v1/world/content?path=/nonexistent/file.txt")
        assert r_404.status_code == 404

        # 4. Meta endpoint includes live_campaign
        r_meta = client.get("/v1/meta")
        assert r_meta.status_code == 200
        assert "live_campaign" in r_meta.json()


def test_scenario_unique_run_ids():
    """Verify repeated runs get unique run_id values using uuid4 (not new_id)."""
    from app.ids import set_seed

    with TestClient(app) as client:
        run_ids = set()
        for _ in range(5):
            set_seed(42)  # Resetting random seed must not cause run_id collisions
            res = client.post("/v1/scenarios/s1/run", json={"step_delay_ms": 0})
            assert res.status_code == 200
            data = res.json()
            run_id = data["run_id"]
            assert len(run_id) == 12
            assert run_id not in run_ids
            run_ids.add(run_id)
        assert len(run_ids) == 5


def test_get_agent_contract_endpoint():
    """Verify GET /v1/agents/{id}/contract returns active contract fields without signature."""
    with TestClient(app) as client:
        # Existing agent
        res = client.get("/v1/agents/procurement-agent/contract")
        assert res.status_code == 200
        data = res.json()
        assert data["agent_id"] == "procurement-agent"
        assert data["role"] == "Procurement Agent"
        assert "allowed_tools" in data
        assert "doc.read" in data["allowed_tools"]
        assert "version" in data
        assert "owner" in data
        assert "rate_limit_per_min" in data
        # Critical requirement: active contract fields (no signature)
        assert "signature" not in data

        # Nonexistent agent returns 404
        res_404 = client.get("/v1/agents/nonexistent-agent/contract")
        assert res_404.status_code == 404


def test_cors_origins_comma_separated():
    """Verify CORS_ORIGINS accepts comma-separated origins and parses them cleanly."""
    from app.config import Settings

    settings = Settings(
        CORS_ORIGINS="http://localhost:5173, http://localhost:5199",
        DOPPEL_ENV="dev",
    )
    assert settings.cors_origins_list == [
        "http://localhost:5173",
        "http://localhost:5199",
    ]


def test_s1l_broadcasts_stream_events():
    """Verify S1L broadcasts scenario_step and scenario_done events on the stream."""
    from app.scenarios.s1l_replay import run_s1l
    from app.stream import get_broadcaster

    broadcaster = get_broadcaster()
    broadcasted_types = []

    def mock_broadcast(event_type: str, payload: dict):
        broadcasted_types.append((event_type, payload.get("scenario_id")))

    original_broadcast = broadcaster.broadcast_sync
    broadcaster.broadcast_sync = mock_broadcast
    try:
        res = run_s1l(reset=True, step_delay_ms=0)
        assert res.id == "s1l"
        event_names = [t[0] for t in broadcasted_types]
        assert "scenario_step" in event_names
        assert "scenario_done" in event_names
        # Confirm model_text is included in replayed step agent_view per Prompt 4d Task 3
        assert len(res.steps) >= 1
        assert "model_text" in res.steps[0].agent_view
        assert res.steps[-1].agent_view.get("model_text") is not None
    finally:
        broadcaster.broadcast_sync = original_broadcast


