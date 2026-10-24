"""Gateway synchronous call execution pipeline per SPEC §5."""

import logging
import time
from typing import Any, Optional
from fastapi import HTTPException

from app.clock import get_clock
from app.config import get_settings
from app.detectors.base import DETECTORS, DetectorContext
from app.engine.response import decide
from app.engine.risk import fuse
from app.gateway.sigil import check
from app.gateway.taint import mark_egress_attempt, update_taint
from app.gateway.tokens import verify
from app.ids import new_id
from app.models import Decision, Event
from app.store import get_store
from app.world.executor import execute, resolve_execution_data_class
from app.world.files import get_file
from app.world.tools import get_tool

logger = logging.getLogger(__name__)


def handle_call(
    session_id: str,
    tool: str,
    args: dict[str, Any],
    purpose: str,
    token: str,
    sigil: Optional[str] = None,
    runtime_fingerprint: Optional[str] = None,
) -> dict[str, Any]:
    """Execute the synchronous 8-step gateway pipeline strictly per SPEC §5."""
    start_time = time.perf_counter()
    store = get_store()
    clock = get_clock()
    settings = get_settings()

    # -------------------------------------------------------------
    # Step 1: Verify the token and session (IAM Checks)
    # -------------------------------------------------------------
    try:
        claims = verify(token)
    except Exception as exc:
        logger.warning("Token verification rejected for call: %s", exc)
        raise HTTPException(status_code=401, detail=f"Unauthorized: {exc}") from exc

    if claims.get("sid") != session_id:
        logger.warning("Token sid '%s' does not match session_id '%s'", claims.get("sid"), session_id)
        raise HTTPException(status_code=401, detail="Unauthorized: Session ID mismatch")

    session = store.get_session(session_id)
    if not session:
        logger.warning("Session %s not found in store", session_id)
        raise HTTPException(status_code=401, detail="Unauthorized: Session not found")

    if session.frozen:
        logger.warning("Call rejected: session %s is frozen", session_id)
        raise HTTPException(status_code=423, detail="Locked: Session is frozen")

    tool_spec = get_tool(tool)
    if not tool_spec:
        logger.warning("Unknown tool requested: %s", tool)
        raise HTTPException(status_code=400, detail=f"Bad Request: Unknown tool '{tool}'")

    if store.is_tool_disabled(tool):
        logger.warning("Call rejected: tool %s is disabled", tool)
        raise HTTPException(status_code=403, detail=f"Forbidden: Tool '{tool}' is disabled")

    # Scopes check: ensure tool's effect is in the token's granted scopes
    tool_effect = tool_spec.effect.value
    token_scopes = claims.get("scopes", [])
    if tool_effect not in token_scopes:
        logger.warning(
            "Forbidden: tool effect '%s' not in token scopes %s for agent %s",
            tool_effect,
            token_scopes,
            session.agent_id,
        )
        raise HTTPException(
            status_code=403,
            detail=f"Forbidden: Scope '{tool_effect}' not granted in token",
        )

    # Note: Gateway does NOT block an action because it deviates from contract!
    # Contract deviation is detected by the detectors in Step 3.

    # -------------------------------------------------------------
    # Step 2: Build the Event
    # -------------------------------------------------------------
    sigil_status = check(session, sigil)

    # Determine target representation
    target: Optional[str] = None
    if tool == "doc.read":
        target = str(args.get("path", ""))
    elif tool == "email.read":
        target = str(args.get("message_id", ""))
    elif tool in ("email.send", "http.post"):
        target = str(args.get("url") or args.get("to") or "")
    elif tool == "agent.delegate":
        target = str(args.get("target_agent", ""))
    elif tool in ("purchase_request.create", "payment.create"):
        target = str(args.get("vendor", ""))

    data_class, sensitivity = resolve_execution_data_class(tool, args)

    bytes_out = 0
    if tool in ("email.send", "http.post"):
        body_content = str(args.get("body", ""))
        bytes_out = len(body_content.encode("utf-8"))

    event = Event(
        event_id=new_id(),
        session_id=session.session_id,
        agent_id=session.agent_id,
        tool=tool,
        args=args,
        purpose=purpose,
        timestamp=clock.now(),
        action_type=tool_effect,
        target=target,
        data_class=data_class,
        sensitivity=sensitivity,
        bytes_out=bytes_out,
        sigil_status=sigil_status,
        sigil_present=bool(sigil and sigil.strip()),
        runtime_fingerprint=runtime_fingerprint,
        token_jti=claims.get("jti"),
        taint_labels_snapshot=list(session.taint_labels),
        taint_refs_snapshot=list(session.taint_refs),
    )

    # -------------------------------------------------------------
    # Step 3: Run the Detectors
    # -------------------------------------------------------------
    contract = store.get_contract(session.agent_id)
    virtual_file = get_file(args.get("path", "")) if tool == "doc.read" else None
    detector_ctx = DetectorContext(
        event=event,
        session=session,
        contract=contract,
        tool_spec=tool_spec,
        file=virtual_file,
        store=store,
        clock=clock,
        settings=settings,
    )

    detector_results = [detector.detect(detector_ctx) for detector in DETECTORS]
    event.detector_results = detector_results

    # -------------------------------------------------------------
    # Step 4: Risk Fusion
    # -------------------------------------------------------------
    event_risk, session_risk, tier, contributions = fuse(
        results=detector_results,
        sensitivity=sensitivity,
        session=session,
    )
    event.risk = event_risk
    event.tier = tier
    # fuse owns session risk (incl. chain-inheritance floor); never let it go down here
    session.risk = max(session.risk, session_risk)
    session.tier = tier

    # -------------------------------------------------------------
    # Step 5: Decide Response
    # -------------------------------------------------------------
    decision = decide(tier=tier, event=event, session=session)
    event.decision = decision

    # -------------------------------------------------------------
    # Step 6: Execute in Simulated World (if allowed) & Update Taint
    # -------------------------------------------------------------
    mark_egress_attempt(session, tool)
    if decision == Decision.allow:
        result = execute(tool=tool, args=args, session=session)
        event.result = result
        update_taint(session=session, tool=tool, args=args, result=result)
    else:
        # Held, sinkholed, or blocked
        result = None
        event.result = None

    # -------------------------------------------------------------
    # Step 7: Persist Event & Session State
    # -------------------------------------------------------------
    latency_ms = (time.perf_counter() - start_time) * 1000.0
    event.latency_ms = round(latency_ms, 2)

    session.updated_at = clock.now()
    session.recent_call_timestamps.append(clock.now())

    store.save_event(event)
    store.save_session(session)

    # -------------------------------------------------------------
    # Step 8: Return Response
    # -------------------------------------------------------------
    return {
        "decision": event.decision.value,
        "result": event.result,
        "risk": event.risk,
        "tier": event.tier.value,
        "new_token": None,
    }
