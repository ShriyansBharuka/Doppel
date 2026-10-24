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
        assert data["tools_pinned"] == 13


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
        assert len(tools) == 13

        names = {t["name"] for t in tools}
        assert "doc.read" in names
        assert "currency.convert" in names
        assert "admin.override_limits" in names

        for t in tools:
            assert len(t["schema_hash"]) == 64


def test_session_freeze_and_restore():
    """Verify POST /v1/sessions/{id}/freeze and POST /v1/sessions/{id}/restore."""
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
        new_token = restore_res.json()["token"]
        assert new_token != token

        # Call with new token succeeds
        call_ok = client.post(
            "/v1/gateway/call",
            headers={"Authorization": f"Bearer {new_token}", "X-Doppel-Sigil": sigil},
            json={"session_id": sid, "tool": "doc.read", "args": {"path": "/procurement/catalog/products.csv"}},
        )
        assert call_ok.status_code == 200
        assert call_ok.json()["status"] == "ok"

