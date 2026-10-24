"""Console management and inspection API routes per SPEC §8, §9, §11."""

from datetime import timedelta
import logging
from typing import Any, Optional
from fastapi import APIRouter, HTTPException, Query

from app.clock import get_clock
from app.config import get_settings
from app.contracts.loader import load_contracts
from app.detectors.d6_drift_cusum import reset_drift_trackers
from app.engine.baseline import init_baseline
from app.gateway.taint import update_taint
from app.gateway.pipeline import sinkhole_call
from app.gateway.tokens import derive_scopes, issue
from app.ids import new_id, set_seed
from app.models import Alert, Approval, Decision, DriftReceipt, Event, SinkholeCapture, Tier
from app.store import get_store
from app.world.executor import execute
from app.world.files import clear_dynamic_watermarks, init_world_files
from app.world.tools import get_tool, init_tools, pin_hashes

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1", tags=["console"])


# -------------------------------------------------------------
# Agent Endpoints
# -------------------------------------------------------------

@router.get("/agents/{agent_id}")
def get_agent_details(agent_id: str) -> dict[str, Any]:
    """Retrieve agent details including associated sessions and maximum observed risk."""
    store = get_store()
    contract = store.get_contract(agent_id)
    if not contract:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")

    sessions = [s for s in store.list_sessions() if s.agent_id == agent_id]
    max_risk = max([s.risk for s in sessions], default=0)

    return {
        "agent_id": agent_id,
        "role": contract.role,
        "purpose": contract.purpose,
        "contract_version": contract.version,
        "sessions": [s.session_id for s in sessions],
        "max_risk": max_risk,
    }


# -------------------------------------------------------------
# Session Management
# -------------------------------------------------------------

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
    data.pop("sigil", None)
    data.pop("token", None)
    data.pop("pending_new_token", None)
    return data


@router.post("/sessions/{session_id}/freeze")
def freeze_session(session_id: str) -> dict[str, Any]:
    """Freeze a session so subsequent calls are rejected with 423 Locked."""
    store = get_store()
    session = store.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Session not found: {session_id}")
    session.frozen = True
    store.save_session(session)
    return {"status": "frozen", "session_id": session_id}


@router.post("/sessions/{session_id}/restore")
def restore_session(session_id: str) -> dict[str, Any]:
    """Complete human restore per SPEC §8:

    Clears risk and tier, leaves decoy mode, resets inherited risk floor,
    blocklists the root-cause content hash, and issues a fresh token.
    """
    store = get_store()
    session = store.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Session not found: {session_id}")

    session.risk = 0
    session.tier = Tier.ALLOW
    session.frozen = False
    session.decoy_mode = False
    session.inherited_risk_floor = 0
    session.removed_scopes = []

    # Blocklist the root-cause content hash
    alert = store.get_alert(session.alert_id) if session.alert_id else None
    if alert and alert.receipt and alert.receipt.root_cause and alert.receipt.root_cause.sha256:
        store.blocklist_content_hash(alert.receipt.root_cause.sha256)
        logger.info("Quarantined root-cause content hash: %s", alert.receipt.root_cause.sha256)
    elif session.taint_refs:
        store.blocklist_content_hash(session.taint_refs[-1].sha256)
        logger.info("Quarantined taint ref content hash: %s", session.taint_refs[-1].sha256)
    if alert:
        alert.status = "resolved"
        store.save_alert(alert)
    session.alert_id = None

    # Fresh full-scope token. The console never sees it: it is handed to the agent as new_token on
    # its next call. Pre-restore token stays valid for a 2-minute grace period (SPEC §8 / Prompt 4a Task 0.b).
    clock = get_clock()
    old_jti = session.current_jti
    if old_jti:
        store.revoke_jti(old_jti, after=clock.now() + timedelta(minutes=2))

    contract = store.get_contract(session.agent_id)
    fresh_jti = new_id()
    session.pending_new_token = issue(
        agent_id=session.agent_id,
        session_id=session.session_id,
        scopes=(derive_scopes(contract) if contract else None) or ["read"],
        act=session.act,
        jti=fresh_jti,
    )
    session.token = session.pending_new_token
    session.current_jti = fresh_jti
    store.save_session(session)

    return {
        "status": "restored",
        "session_id": session_id,
    }


# -------------------------------------------------------------
# Alerts & Drift Receipts
# -------------------------------------------------------------

@router.get("/alerts")
def list_alerts(session_id: Optional[str] = Query(None)) -> list[Alert]:
    """List drift alerts, optionally filtered by session_id."""
    store = get_store()
    return store.list_alerts(session_id=session_id)


@router.get("/alerts/{alert_id}")
def get_alert(alert_id: str) -> Alert:
    """Retrieve a specific alert by id."""
    store = get_store()
    alert = store.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")
    return alert


@router.get("/alerts/{alert_id}/receipt")
def get_drift_receipt(alert_id: str) -> DriftReceipt:
    """Retrieve the explainable Drift Receipt for an alert."""
    store = get_store()
    alert = store.get_alert(alert_id)
    if not alert or not alert.receipt:
        raise HTTPException(status_code=404, detail=f"Drift Receipt for alert '{alert_id}' not found")
    return alert.receipt


# -------------------------------------------------------------
# Human Approvals
# -------------------------------------------------------------

@router.get("/approvals")
def list_approvals(
    status: Optional[str] = Query(None),
    session_id: Optional[str] = Query(None),
) -> list[Approval]:
    """List human approval requests, optionally filtered by status (e.g. pending)."""
    store = get_store()
    return store.list_approvals(session_id=session_id, status=status)


@router.post("/alerts/{target_id}/approve")
def approve_action(target_id: str) -> dict[str, Any]:
    """Approve a held call (target_id can be approval_id or alert_id). Executes held tool."""
    store = get_store()
    clock = get_clock()

    # Look up by approval_id first, then by alert_id
    approval = store.get_approval(target_id)
    if not approval:
        alert = store.get_alert(target_id)
        if alert:
            pending = store.list_approvals(session_id=alert.session_id, status="pending")
            if pending:
                approval = pending[0]

    if not approval:
        raise HTTPException(status_code=404, detail=f"Pending approval '{target_id}' not found")

    if approval.status != "pending":
        raise HTTPException(status_code=409, detail=f"Approval is already {approval.status}")

    session = store.get_session(approval.session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found for approval")

    ev = store.get_event(approval.event_id)
    if session.decoy_mode or session.tier == Tier.ISOLATE:
        # Session went rogue while the call waited: never let the approval reach the real world
        res = sinkhole_call(session, approval.tool, approval.args, ev.target if ev else None)
        decision = Decision.sinkhole
    else:
        res = execute(tool=approval.tool, args=approval.args, session=session)
        update_taint(session=session, tool=approval.tool, args=approval.args, result=res)
        decision = Decision.allow

    # Update event record
    if ev:
        ev.decision = decision
        ev.result = res
        store.save_event(ev)

    # Mark approval resolved
    approval.status = "approved"
    approval.note = "approved by human"
    approval.resolved_at = clock.now()
    store.save_approval(approval)
    store.save_session(session)
    from app.stream import get_broadcaster
    get_broadcaster().broadcast_sync("approval", approval.model_dump())

    return {
        "status": "approved",
        "approval_id": approval.approval_id,
        "result": res,
    }


@router.post("/alerts/{target_id}/deny")
def deny_action(target_id: str) -> dict[str, Any]:
    """Deny and drop a held call (target_id can be approval_id or alert_id)."""
    store = get_store()
    clock = get_clock()

    approval = store.get_approval(target_id)
    if not approval:
        alert = store.get_alert(target_id)
        if alert:
            pending = store.list_approvals(session_id=alert.session_id, status="pending")
            if pending:
                approval = pending[0]

    if not approval:
        raise HTTPException(status_code=404, detail=f"Pending approval '{target_id}' not found")

    if approval.status != "pending":
        raise HTTPException(status_code=409, detail=f"Approval is already {approval.status}")

    ev = store.get_event(approval.event_id)
    if ev:
        ev.decision = Decision.block
        store.save_event(ev)

    approval.status = "denied"
    approval.note = "denied by human"
    approval.resolved_at = clock.now()
    store.save_approval(approval)
    from app.stream import get_broadcaster
    get_broadcaster().broadcast_sync("approval", approval.model_dump())

    return {
        "status": "denied",
        "approval_id": approval.approval_id,
    }


# -------------------------------------------------------------
# Tool Re-Approval
# -------------------------------------------------------------

@router.post("/tools/{name}/reapprove")
def reapprove_tool(name: str) -> dict[str, Any]:
    """Re-pin tool schema hash and re-enable tool after integrity alert."""
    store = get_store()
    ts = get_tool(name)
    if not ts:
        raise HTTPException(status_code=404, detail=f"Tool '{name}' not found")

    store.pin_tool_hash(name, ts.schema_hash)
    store.enable_tool(name)
    logger.info("Reapproved tool '%s' with hash %s", name, ts.schema_hash)

    return {
        "status": "reapproved",
        "tool": name,
        "schema_hash": ts.schema_hash,
    }


# -------------------------------------------------------------
# Sinkhole & Events & Reset
# -------------------------------------------------------------

@router.get("/sinkhole")
def list_sinkhole() -> list[SinkholeCapture]:
    """Retrieve captured payloads routed to the sinkhole evidence locker."""
    store = get_store()
    return store.list_sinkhole_captures()


@router.get("/events")
def list_events(session_id: Optional[str] = Query(None)) -> list[Event]:
    """List recorded gateway events, optionally filtered by session_id."""
    store = get_store()
    return store.list_events(session_id=session_id)


@router.get("/world/state")
def get_world_state() -> dict[str, Any]:
    """Return real world state per SPEC §11 / Prompt 4a Task 0.g."""
    store = get_store()
    return {
        "purchase_requests": store.get_purchase_requests(),
        "payments": store.get_payments(),
        "egress_log": store.get_egress_logs(),
        "delegations": store.get_delegations(),
    }


@router.post("/reset")
def reset_state() -> dict[str, Any]:
    """Clear store, rebuild world, re-pin tool hashes, and reload verified contracts."""
    store = get_store()
    settings = get_settings()

    store.reset()
    clear_dynamic_watermarks()
    reset_drift_trackers()
    set_seed(settings.SCENARIO_SEED)
    get_clock().reset()

    init_world_files(settings.SCENARIO_SEED)
    init_tools()
    pin_hashes(store)

    contracts = load_contracts()
    for contract in contracts.values():
        store.save_contract(contract)

    init_baseline(settings.SCENARIO_SEED)

    return {
        "status": "reset",
        "contracts_loaded": len(contracts),
        "tools_pinned": len(store.get_all_pinned_tool_hashes()),
    }
