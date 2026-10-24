"""D3 Sequence detector: evaluates tool transition probability against Markov baseline."""

from app.detectors.base import DetectorContext
from app.engine.baseline import get_baseline
from app.models import DetectorResult


class SequenceDetector:
    """Detector D3: Evaluates first-order Markov transition P(tool_t | tool_t-1)."""

    name = "sequence"

    def detect(self, ctx: DetectorContext) -> DetectorResult:
        baseline = get_baseline()
        agent_id = ctx.session.agent_id
        current_tool = ctx.event.tool

        events = ctx.store.list_events(session_id=ctx.session.session_id)
        if not events:
            # First tool call in session
            return DetectorResult(
                name=self.name,
                score=0.0,
                evidence=[],
                tags=["OWASP:ASI01", "OWASP:ASI02"],
            )

        prev_tool = events[-1].tool
        score = baseline.score_transition(agent_id, prev_tool, current_tool, ctx.contract)

        evidence: list[str] = []
        if score >= 0.8:
            evidence.append(
                f"Unseen tool transition: {prev_tool} -> {current_tool} for {agent_id}"
            )
        elif score >= 0.6:
            evidence.append(
                f"Unseen tool transition: {prev_tool} -> {current_tool} between common on-contract tools for {agent_id}"
            )
        elif score >= 0.5:
            evidence.append(
                f"Rare tool transition: {prev_tool} -> {current_tool} (P < 0.02) for {agent_id}"
            )

        return DetectorResult(
            name=self.name,
            score=round(score, 2),
            evidence=evidence,
            tags=["OWASP:ASI01", "OWASP:ASI02"],
        )
