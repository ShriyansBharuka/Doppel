"""Risk fusion engine stub for Prompt 3."""

from typing import Optional

from app.models import Contribution, DetectorResult, Sensitivity, SessionState, Tier


def fuse(
    results: list[DetectorResult],
    sensitivity: Optional[Sensitivity],
    session: SessionState,
) -> tuple[int, int, Tier, list[Contribution]]:
    """Fuse individual detector results into event risk, session risk, and tier.

    Prompt 2 stub returns (0, 0, Tier.ALLOW, []). Full Noisy-OR fusion implemented in Prompt 3.
    """
    return 0, session.risk, Tier.ALLOW, []
