"""D8 Token Context detector: identifies token replay and unhuman execution speed."""

from app.detectors.base import DetectorContext
from app.models import DetectorResult


class TokenContextDetector:
    """Detector D8: Detects runtime fingerprint divergence and sub-50ms automated machine loops."""

    name = "token_context"

    def detect(self, ctx: DetectorContext) -> DetectorResult:
        session = ctx.session
        orig_fp = session.original_fingerprint
        pres_fp = ctx.event.runtime_fingerprint

        scores: list[tuple[float, str]] = []

        # 1. Runtime fingerprint mismatch
        if orig_fp and pres_fp and orig_fp != pres_fp:
            scores.append((
                0.8,
                f"Runtime fingerprint mismatch: session initialized on '{orig_fp}' but call invoked from '{pres_fp}'",
            ))

        # 2. Sub-50ms machine speed check (≥3 consecutive gaps < 50 ms)
        call_timestamps = session.recent_call_timestamps
        if len(call_timestamps) >= 4:
            gaps = [
                (t2 - t1).total_seconds() * 1000.0
                for t1, t2 in zip(call_timestamps[-4:-1], call_timestamps[-3:])
            ]
            if len(gaps) >= 3 and all(gap < 50.0 for gap in gaps[-3:]):
                scores.append((
                    0.5,
                    f"Machine-speed execution loop detected: 3 consecutive calls with <50ms latency ({[round(g, 1) for g in gaps[-3:]]} ms)",
                ))

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
