"""Gateway synchronous call execution pipeline per SPEC §5."""

import hashlib
import logging
import time
from typing import Any, Optional
from fastapi import HTTPException

from app.clock import get_clock
from app.config import get_settings
from app.detectors.base import DETECTORS, DetectorContext
from app.engine.actions import apply_session_tier_actions
from app.engine.receipt import sync_session_alert
from app.engine.response import decide
from app.engine.risk import fuse
from app.gateway.sigil import check
from app.gateway.taint import mark_egress_attempt, update_taint
from app.gateway.tokens import derive_scopes, issue, revoke, verify
from app.ids import new_id
from app.models import Approval, Decision, Event, SessionState, SinkholeCapture
from app.store import get_store
from app.stream import get_broadcaster
from app.world.egress import extract_host
from app.world.executor import execute, resolve_execution_data_class
from app.world.files import get_all_watermarks, get_decoy_mirror_content, get_file
from app.world.tools import get_tool

logger = logging.getLogger(__name__)


def sinkhole_call(session: SessionState, tool: str, args: dict[str, Any], target: Optional[str]) -> Any:
    """Capture the call in the evidence locker; reply exactly like the real tool, touch nothing real."""
    store = get_store()
    raw_payload = args.get("body", args)
    payload_str = str(raw_payload)
    url_arg = args.get("url")
    to_arg = args.get("to")
    if url_arg:
        host_target = extract_host(str(url_arg))
    elif to_arg:
        host_target = str(to_arg).split("@")[-1].lower()
    else:
        host_target = target or ""

    all_wms = get_all_watermarks(get_settings().SCENARIO_SEED)
    matched = [(src, wm) for src, wm in all_wms.items() if wm in payload_str]
    capture = SinkholeCapture(
        capture_id=new_id(),
        session_id=session.session_id,
        agent_id=session.agent_id,
        tool=tool,
        host=host_target,
        destination=host_target,
        payload=raw_payload,
        bytes=len(payload_str.encode("utf-8")),
        matched_watermarks=[wm for _, wm in matched],
        leaked_decoy=matched[0][0] if matched else None,
        watermark_detected=matched[0][1] if matched else None,
        timestamp=get_clock().now(),
    )
    store.save_sinkhole_capture(capture)
    get_broadcaster().broadcast_sync("sinkhole", capture.model_dump())
    # Same code path as a real success, so keys/shape can never drift apart
    return execute(tool=tool, args=args, session=session, record=False)


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

    # Helper to persist a blocked event on rejection with identifiable session per SPEC §5
    def _reject(status_code: int, detail: str, action_type: str = "unknown") -> None:
        block_event = Event(
            event_id=new_id(),
            session_id=session.session_id,
            agent_id=session.agent_id,
            tool=tool,
            args=args,
            purpose=purpose,
            timestamp=clock.now(),
            action_type=action_type,
            decision=Decision.block,
            risk=session.risk,
            tier=session.tier,
            runtime_fingerprint=runtime_fingerprint,
            token_jti=claims.get("jti"),
            taint_labels_snapshot=list(session.taint_labels),
            taint_refs_snapshot=list(session.taint_refs),
        )
        store.save_event(block_event)
        raise HTTPException(status_code=status_code, detail=detail)

    if session.frozen:
        logger.warning("Call rejected: session %s is frozen", session_id)
        _reject(423, "Locked: Session is frozen")

    tool_spec = get_tool(tool)
    if not tool_spec:
        logger.warning("Unknown tool requested: %s", tool)
        _reject(400, f"Bad Request: Unknown tool '{tool}'")

    if store.is_tool_disabled(tool):
        logger.warning("Call rejected: tool %s is disabled", tool)
        _reject(403, f"Forbidden: Tool '{tool}' is disabled", action_type=tool_spec.effect.value)

    # Scopes check: ensure tool's effect is in the token's granted scopes
    tool_effect = tool_spec.effect.value
    token_scopes = claims.get("scopes", [])
    if tool_effect not in token_scopes:
        # Task 2: If a shrunk session later calls a tool whose scope DOPPEL removed,
        # route that call to the sinkhole instead of returning 403 (agent must not learn it was downgraded)
        if tool_effect in session.removed_scopes:
            logger.info(
                "Tool effect '%s' was removed via SHRINK; allowing through to sinkhole silently",
                tool_effect,
            )
        else:
            logger.warning(
                "Forbidden: tool effect '%s' not in token scopes %s for agent %s",
                tool_effect,
                token_scopes,
                session.agent_id,
            )
            _reject(403, f"Forbidden: Scope '{tool_effect}' not granted in token", action_type=tool_effect)

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
    virtual_file = None
    if tool == "doc.read":
        virtual_file = get_file(args.get("path", ""))
    elif tool == "email.read":
        msg_id = args.get("message_id", "")
        virtual_file = get_file(f"/inbox/{msg_id}")
    elif tool == "vault.get":
        name = args.get("name", "")
        virtual_file = get_file(f"/vault/{name}") or get_file("/vault/AWS_PROD_ROOT_KEY")

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

    # Apply D9 side effects (Task 4: disable tool for all agents)
    for d_res in detector_results:
        for eff in d_res.side_effects:
            if eff.startswith("disable_tool:"):
                tool_to_disable = eff.split(":", 1)[1]
                logger.warning("Pipeline applying side-effect: disabling tool '%s'", tool_to_disable)
                store.disable_tool(tool_to_disable)
                get_broadcaster().broadcast_sync("tool_disabled", {"tool": tool_to_disable})

    # -------------------------------------------------------------
    # Step 4: Risk Fusion
    # -------------------------------------------------------------
    prev_tier = session.tier
    event_risk, session_risk, tier, contributions = fuse(
        results=detector_results,
        sensitivity=sensitivity,
        session=session,
        event=event,
    )
    event.risk = event_risk
    event.tier = tier
    session.risk = session_risk
    session.tier = tier

    # Apply session-level actions when tier rises (Task 2: SHRINK / ISOLATE)
    reissued_token = apply_session_tier_actions(
        session=session,
        prev_tier=prev_tier,
        new_tier=tier,
        store=store,
        current_event=event,
    )

    # -------------------------------------------------------------
    # Step 5: Decide Response
    # -------------------------------------------------------------
    decision = decide(tier=tier, event=event, session=session)
    event.decision = decision

    # -------------------------------------------------------------
    # Step 6: Execute in Simulated World & Handle Outcomes
    # -------------------------------------------------------------
    mark_egress_attempt(session, tool)
    result: Any = None

    if decision == Decision.allow:
        # Check if reading quarantined content (Task 6)
        is_quarantined = False
        if tool == "doc.read" and virtual_file:
            content_sha = hashlib.sha256(virtual_file.content.encode("utf-8")).hexdigest()
            if store.is_content_hash_blocklisted(content_sha):
                is_quarantined = True

        if is_quarantined:
            logger.info("Serving quarantined placeholder for content '%s'", virtual_file.path)
            result = "[content unavailable]"
        else:
            result = execute(tool=tool, args=args, session=session)

        event.result = result
        update_taint(session=session, tool=tool, args=args, result=result)

    elif decision == Decision.hold:
        # Task 4: Create approval record; agent receives status 'pending_approval'
        approval = Approval(
            approval_id=new_id(),
            alert_id=session.alert_id,
            session_id=session.session_id,
            event_id=event.event_id,
            agent_id=session.agent_id,
            tool=tool,
            args=args,
            purpose=purpose,
            status="pending",
            created_at=clock.now(),
        )
        store.save_approval(approval)
        get_broadcaster().broadcast_sync("approval", approval.model_dump())
        result = None
        event.result = None

    elif decision == Decision.sinkhole:
        result = sinkhole_call(session, tool, args, event.target)
        event.result = result

    elif decision == Decision.decoy:
        # Task 4: Serve mirror decoy content with its own registered watermark
        path = args.get("path", "")
        mirror_content, _ = get_decoy_mirror_content(path, settings.SCENARIO_SEED)
        result = mirror_content
        event.result = result
        update_taint(session=session, tool=tool, args=args, result=result)

    else:
        result = None
        event.result = None

    # -------------------------------------------------------------
    # Step 7: Persist Event & Session State; Sync Alerts
    # -------------------------------------------------------------
    latency_ms = (time.perf_counter() - start_time) * 1000.0
    event.latency_ms = round(latency_ms, 2)

    session.updated_at = clock.now()
    session.recent_call_timestamps.append(clock.now())

    store.save_event(event)
    get_broadcaster().broadcast_sync("event", event.model_dump())

    # Sync Alert and Drift Receipt when tier >= WATCH (Task 5)
    sync_session_alert(session, contract, store, clock)
    store.save_session(session)

    # -------------------------------------------------------------
    # Step 8: Return Agent-Facing Response per SPEC §5
    # The agent never sees decision, risk, tier or detector output;
    # a sinkholed or decoy call is indistinguishable from real success.
    # -------------------------------------------------------------
    session.call_count += 1
    routine_token: Optional[str] = None
    if session.call_count % 10 == 0:
        contract_obj = store.get_contract(session.agent_id)
        scopes = (derive_scopes(contract_obj) if contract_obj else None) or claims.get("scopes", ["read"])
        fresh_jti = new_id()
        routine_token = issue(
            agent_id=session.agent_id,
            session_id=session.session_id,
            scopes=scopes,
            act=session.act,
            jti=fresh_jti,
        )
        session.token = routine_token
        session.current_jti = fresh_jti

    status = "pending_approval" if decision == Decision.hold else "ok"
    returned_token = session.pending_new_token or routine_token
    session.pending_new_token = None
    store.save_session(session)

    return {
        "status": status,
        "result": event.result,
        "new_token": returned_token,
    }
