"""Response decision engine per SPEC §8 per-call outcome ladder."""

import logging
from typing import Optional

from app.models import Decision, Event, Sensitivity, SessionState, Tier
from app.world.files import get_all_watermarks, get_file
from app.world.tools import get_tool

logger = logging.getLogger(__name__)


def decide(tier: Tier, event: Event, session: SessionState) -> Decision:
    """Decide response action for current call per SPEC §8 table.

    Returns exactly one of: allow | hold | sinkhole | decoy | block.
    """
    tool_spec = get_tool(event.tool)
    action_type = event.action_type or (tool_spec.effect.value if tool_spec else "read")
    target_file = get_file(event.target or "") if event.target else None

    # 1. Any tier: reading a decoy file/tool/secret -> allow (keep the trap open!)
    is_decoy_touch = False
    if target_file and target_file.is_decoy:
        is_decoy_touch = True
    elif tool_spec and tool_spec.is_decoy:
        is_decoy_touch = True
    elif event.target and "/vault/" in event.target:
        is_decoy_touch = True
    else:
        # Check D5 evidence for decoy touch
        for det in event.detector_results:
            if det.name == "decoy" and det.score >= 1.0:
                if any("decoy" in ev.lower() and "watermark" not in ev.lower() for ev in det.evidence):
                    is_decoy_touch = True
                    break

    if is_decoy_touch and action_type == "read":
        logger.info("Reading decoy asset: allowing call to keep trap open per SPEC §8")
        return Decision.allow

    # 2. Any tier: egress whose body contains a watermark -> sinkhole
    if action_type == "egress":
        # Check D5 detector result or watermark in args/body
        for det in event.detector_results:
            if det.name == "decoy" and det.score >= 1.0:
                if any("watermark" in ev.lower() or "exfiltration" in ev.lower() for ev in det.evidence):
                    logger.warning("Watermark detected in egress body: routing to sinkhole")
                    return Decision.sinkhole

        # Direct payload watermark check
        watermarks = get_all_watermarks().values()
        args_str = str(event.args)
        if any(wm in args_str for wm in watermarks) or "DPL-WM-" in args_str:
            logger.warning("Watermark string in egress args: routing to sinkhole")
            return Decision.sinkhole

    # 3. ISOLATE tier (decoy mode)
    if tier == Tier.ISOLATE or session.decoy_mode:
        # Writes, egress, delegation go to sinkhole (success-shaped reply)
        if action_type in ("write", "egress", "delegate") or event.tool in ("payment.create", "purchase_request.create"):
            logger.warning("ISOLATE tier: routing action '%s' to sinkhole", event.tool)
            return Decision.sinkhole

        # Reads of confidential or restricted data -> serve decoy content
        if event.sensitivity in (Sensitivity.confidential, Sensitivity.restricted):
            logger.warning("ISOLATE tier: serving decoy content for sensitive read of '%s'", event.target)
            return Decision.decoy

        # Other allowed non-sensitive reads execute
        return Decision.allow

    # 4. SHRINK tier
    if tier == Tier.SHRINK:
        # Egress, delegation, or any scope removed by Doppel -> sinkhole
        if action_type in ("egress", "delegate") or action_type in session.removed_scopes:
            logger.warning("SHRINK tier: sinkholing restricted action '%s'", event.tool)
            return Decision.sinkhole
        return Decision.allow

    # 5. WATCH tier
    if tier == Tier.WATCH:
        # Egress, delegation, payments, writes to confidential/restricted -> hold
        is_held = (
            action_type in ("egress", "delegate")
            or event.tool in ("payment.create", "purchase_request.create")
            or (action_type == "write" and event.sensitivity in (Sensitivity.confidential, Sensitivity.restricted))
        )
        if is_held:
            logger.info("WATCH tier: holding action '%s' for human approval", event.tool)
            return Decision.hold
        return Decision.allow

    # 6. ALLOW tier
    return Decision.allow
