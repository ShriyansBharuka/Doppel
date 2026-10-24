"""D6 Drift CUSUM detector: tracks long-horizon tool distribution divergence."""

import math
from typing import Optional

from app.detectors.base import DetectorContext
from app.engine.baseline import get_baseline
from app.models import DetectorResult


def jensen_shannon_divergence(p: dict[str, float], q: dict[str, float]) -> float:
    """Calculate Jensen-Shannon divergence with log base 2 between two discrete probability distributions.

    Returns 0.0 for identical distributions and 1.0 for disjoint distributions.
    """
    keys = set(p.keys()) | set(q.keys())
    kl_p = 0.0
    kl_q = 0.0

    for k in keys:
        pk = p.get(k, 0.0)
        qk = q.get(k, 0.0)
        mk = 0.5 * (pk + qk)
        if mk > 0.0:
            if pk > 0.0:
                kl_p += pk * math.log2(pk / mk)
            if qk > 0.0:
                kl_q += qk * math.log2(qk / mk)

    return 0.5 * kl_p + 0.5 * kl_q


class CusumTracker:
    """Page's Cumulative Sum (CUSUM) control chart tracker per agent."""

    def __init__(self, agent_id: str) -> None:
        self.agent_id = agent_id
        self.mu0: float = 0.0
        self.kappa: float = 0.02
        self.h: float = 0.20
        self.s_t: float = 0.0
        self.day_history: list[float] = []

    def fit_anchor(self, training_day_divergences: list[float]) -> None:
        """Fit baseline parameters μ0, κ, and h from training day divergences vs anchor."""
        if not training_day_divergences:
            self.mu0 = 0.01
            self.kappa = 0.02
            self.h = 0.15
            return

        self.mu0 = sum(training_day_divergences) / len(training_day_divergences)
        variance = sum((x - self.mu0) ** 2 for x in training_day_divergences) / len(training_day_divergences)
        std = math.sqrt(variance)
        std_effective = max(std, 0.01)

        self.kappa = 0.5 * std_effective
        self.h = 5.0 * std_effective
        self.s_t = 0.0

    def update_day(self, d_t: float) -> float:
        """Update CUSUM accumulator: S_t = max(0, S_{t-1} + d_t - μ0 - κ)."""
        self.s_t = max(0.0, self.s_t + d_t - self.mu0 - self.kappa)
        self.day_history.append(self.s_t)
        return self.s_t

    def get_score(self) -> float:
        """Return CUSUM score clamped between 0 and 1: min(1, S_t / h)."""
        if self.h <= 0.0:
            return 1.0 if self.s_t > 0 else 0.0
        return min(1.0, self.s_t / self.h)

    def is_alarm(self) -> bool:
        """Return True if accumulator exceeds decision threshold h."""
        return self.s_t > self.h


class EWMATracker:
    """Exponentially Weighted Moving Average rolling-baseline comparator."""

    def __init__(self, alpha: float = 0.2) -> None:
        self.alpha = alpha
        self.baseline: Optional[dict[str, float]] = None

    def update(self, day_dist: dict[str, float]) -> float:
        """Update rolling baseline and return divergence against previous day's baseline."""
        if self.baseline is None:
            self.baseline = dict(day_dist)
            return 0.0

        # Divergence vs current rolling baseline
        d = jensen_shannon_divergence(day_dist, self.baseline)

        # Adapt rolling baseline: B_t = α * P_t + (1 - α) * B_{t-1}
        keys = set(day_dist.keys()) | set(self.baseline.keys())
        updated: dict[str, float] = {}
        for k in keys:
            pk = day_dist.get(k, 0.0)
            bk = self.baseline.get(k, 0.0)
            updated[k] = self.alpha * pk + (1.0 - self.alpha) * bk

        total = sum(updated.values())
        self.baseline = {k: v / total for k, v in updated.items()} if total > 0 else updated
        return d


# Global per-agent CUSUM and EWMA trackers
_cusum_trackers: dict[str, CusumTracker] = {}
_ewma_trackers: dict[str, EWMATracker] = {}


def get_cusum_tracker(agent_id: str) -> CusumTracker:
    """Retrieve or create CusumTracker for an agent."""
    if agent_id not in _cusum_trackers:
        _cusum_trackers[agent_id] = CusumTracker(agent_id)
    return _cusum_trackers[agent_id]


def get_ewma_tracker(agent_id: str) -> EWMATracker:
    """Retrieve or create EWMATracker for an agent."""
    if agent_id not in _ewma_trackers:
        _ewma_trackers[agent_id] = EWMATracker()
    return _ewma_trackers[agent_id]


class DriftCusumDetector:
    """Detector D6: Multi-day CUSUM drift detection against frozen anchor distribution."""

    name = "drift_cusum"

    def detect(self, ctx: DetectorContext) -> DetectorResult:
        agent_id = ctx.session.agent_id
        tracker = get_cusum_tracker(agent_id)
        score = tracker.get_score()

        evidence: list[str] = []
        if tracker.is_alarm():
            evidence.append(
                f"Multi-day distribution drift detected for {agent_id}: CUSUM S_t={tracker.s_t:.3f} > threshold h={tracker.h:.3f}"
            )

        return DetectorResult(
            name=self.name,
            score=round(score, 2),
            evidence=evidence,
            tags=["OWASP:ASI01"],
        )
