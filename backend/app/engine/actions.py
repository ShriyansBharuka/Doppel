"""Session-level actions triggered when a session's security tier escalates per SPEC §8."""

import logging
from typing import Optional

from app.engine.risk import derive_tier
from app.gateway.tokens import reissue
from app.models import Event, SessionState, Tier
from app.store import Store
from app.world.tools import get_tool

logger = logging.getLogger(__name__)

TIER_ORDER: dict[Tier, int] = {
    Tier.ALLOW: 0,
    Tier.WATCH: 1,
    Tier.SHRINK: 2,
    Tier.ISOLATE: 3,
}


def apply_session_tier_actions(
    session: SessionState,
    prev_tier: Tier,
    new_tier: Tier,
    store: Store,
    current_event: Optional[Event] = None,
) -> Optional[str]:
    """Apply session-level actions when the session tier rises.

    Returns new_token if a token rotation occurred (e.g. SHRINK tier).
    """
    if TIER_ORDER.get(new_tier, 0) <= TIER_ORDER.get(prev_tier, 0):
        # Tier did not rise
        return None

    issued_token: Optional[str] = None

    # 1. Escalation to SHRINK (applied once)
    if new_tier == Tier.SHRINK and prev_tier in (Tier.ALLOW, Tier.WATCH):
        logger.warning(
            "Session %s escalated to SHRINK. Recording removed scopes without reissuing token.",
            session.session_id,
        )
        contract = store.get_contract(session.agent_id)
        current_scopes: list[str] = []
        if contract:
            for tool_name in contract.allowed_tools:
                ts = get_tool(tool_name)
                if ts and ts.effect.value not in current_scopes:
                    current_scopes.append(ts.effect.value)

        # Remove write, egress, delegate (enforced server-side)
        removed = [s for s in ("write", "egress", "delegate") if s in current_scopes]
        session.removed_scopes = list(set(session.removed_scopes + removed))

    # 2. Escalation to ISOLATE (decoy mode)
    if new_tier == Tier.ISOLATE and prev_tier != Tier.ISOLATE:
        logger.warning(
            "Session %s escalated to ISOLATE. Entering decoy mode ('mirror world').",
            session.session_id,
        )
        session.decoy_mode = True

        # Snapshot session events
        existing_events = store.list_events(session_id=session.session_id)
        event_ids = [e.event_id for e in existing_events]
        if current_event and current_event.event_id not in event_ids:
            event_ids.append(current_event.event_id)
        session.snapshot_event_ids = event_ids

        # Raise inherited risk floor on existing descendant sessions
        child_floor = round(0.7 * session.risk)
        all_sessions = store.list_sessions()
        for candidate in all_sessions:
            if candidate.parent_session_id == session.session_id:
                candidate.inherited_risk_floor = max(candidate.inherited_risk_floor, child_floor)
                candidate.risk = max(candidate.risk, candidate.inherited_risk_floor)
                candidate.tier = derive_tier(candidate.risk)
                store.save_session(candidate)
                logger.info(
                    "Applied inherited risk floor %d to child session %s",
                    child_floor,
                    candidate.session_id,
                )

    return issued_token
