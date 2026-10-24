"""Response decision engine stub for Prompt 3."""

from app.models import Decision, Event, SessionState, Tier


def decide(tier: Tier, event: Event, session: SessionState) -> Decision:
    """Decide response action based on tier, event context, and session state.

    Prompt 2 stub returns Decision.allow. Reversible response ladder implemented in Prompt 3.
    """
    return Decision.allow
