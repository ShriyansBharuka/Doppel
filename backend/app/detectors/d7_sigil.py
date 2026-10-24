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
        flags: set[str] = set()

        if status == "wrong":
            scores.append((1.0, "Presented sigil does not match session canary token"))
            flags.add("sigil_wrong")
        elif status == "missing":
            scores.append((0.9, "Missing X-Doppel-Sigil header on agent tool invocation"))
            flags.add("sigil_missing")

        if not purpose:
            scores.append((0.3, "Tool invocation has empty or whitespace purpose"))
            flags.add("purpose_empty")

        if not scores:
            return DetectorResult(
                name=self.name,
                score=0.0,
                evidence=[],
                tags=["OWASP:ASI03"],
                flags=set(),
            )

        max_score, top_evidence = max(scores, key=lambda x: x[0])
        return DetectorResult(
            name=self.name,
            score=max_score,
            evidence=[top_evidence],
            tags=["OWASP:ASI03"],
            flags=flags,
        )
