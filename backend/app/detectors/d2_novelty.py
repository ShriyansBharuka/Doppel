"""D2 Novelty detector: tool frequency anomaly relative to agent and peer baseline."""

from app.detectors.base import DetectorContext
from app.engine.baseline import get_baseline
from app.models import DetectorResult


class NoveltyDetector:
    """Detector D2: Scores frequency anomaly of the invoked tool against learned baseline."""

    name = "novelty"

    def detect(self, ctx: DetectorContext) -> DetectorResult:
        baseline = get_baseline()
        tool = ctx.event.tool
        agent_id = ctx.session.agent_id

        score = baseline.score_novelty(agent_id, tool)
        p = baseline.calculate_novelty_p(agent_id, tool)

        evidence: list[str] = []
        if score > 0.3:
            evidence.append(
                f"Tool '{tool}' is anomalous for {agent_id} (probability P={p:.4f})"
            )

        return DetectorResult(
            name=self.name,
            score=round(score, 2),
            evidence=evidence,
            tags=["OWASP:ASI01", "OWASP:ASI02"],
        )
