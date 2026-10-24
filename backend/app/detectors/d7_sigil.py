"""D7 Sigil detector: validates per-session intent canary and declared purpose."""

from app.detectors.base import DetectorContext
from app.models import DetectorResult


class SigilDetector:
    """Detector D7: Checks presence and validity of session canary sigil and action purpose."""

    name = "sigil"

    def detect(self, ctx: DetectorContext) -> DetectorResult:
        status = ctx.event.sigil_status
        purpose = ctx.event.purpose.strip()

        scores: list[tuple[float, str]] = []

        if status == "wrong":
            scores.append((1.0, "Presented sigil does not match session canary token"))
        elif status == "missing":
            scores.append((0.9, "Missing X-Doppel-Sigil header on agent tool invocation"))

        if not purpose:
            scores.append((0.3, "Tool invocation has empty or whitespace purpose"))

        if not scores:
            return DetectorResult(
                name=self.name,
                score=0.0,
                evidence=[],
                tags=["OWASP:ASI03"],
            )

        max_score, top_evidence = max(scores, key=lambda x: x[0])
        return DetectorResult(
            name=self.name,
            score=max_score,
            evidence=[top_evidence],
            tags=["OWASP:ASI03"],
        )
