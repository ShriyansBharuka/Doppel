"""Console management and inspection API routes."""

from typing import Any, Optional
from fastapi import APIRouter, HTTPException, Query

from app.config import get_settings
from app.contracts.loader import load_contracts
from app.models import Event
from app.store import get_store
from app.world.files import init_world_files
from app.world.tools import init_tools, pin_hashes

router = APIRouter(prefix="/v1", tags=["console"])


@router.get("/sessions/{session_id}")
def get_session(session_id: str) -> dict[str, Any]:
    """Retrieve session details.

    CRITICAL SECURITY INVARIANT: The private sigil value is NEVER returned.
    """
    store = get_store()
    session = store.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Session not found: {session_id}")

    data = session.model_dump()
    # Mask private intent canary sigil from console inspection
    data.pop("sigil", None)
    # The live bearer token is a credential too; the console never needs it
    data.pop("token", None)
    return data


@router.get("/events")
def list_events(session_id: Optional[str] = Query(None)) -> list[Event]:
    """List recorded gateway events, optionally filtered by session_id."""
    store = get_store()
    return store.list_events(session_id=session_id)


@router.post("/reset")
def reset_state() -> dict[str, Any]:
    """Clear store, rebuild world, re-pin tool hashes, and reload verified contracts."""
    store = get_store()
    settings = get_settings()

    store.reset()
    init_world_files(settings.SCENARIO_SEED)
    init_tools()
    pin_hashes(store)

    contracts = load_contracts()
    for contract in contracts.values():
        store.save_contract(contract)

    return {
        "status": "reset",
        "contracts_loaded": len(contracts),
        "tools_pinned": len(store.get_all_pinned_tool_hashes()),
    }
