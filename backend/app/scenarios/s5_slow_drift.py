"""Scenario S5: Multi-Day Slow Drift Detection (CUSUM vs EWMA) (SPEC §10)."""

from collections import Counter
import logging
import random
import statistics
from typing import Any, Optional

from app.agents.scripted import ScriptedAgent
from app.clock import get_clock
from app.config import get_settings
from app.detectors.d6_drift_cusum import (
    EWMATracker,
    get_cusum_tracker,
    jensen_shannon_divergence,
)
from app.engine.baseline import get_baseline
from app.scenarios.grammars import _generate_procurement_session, generate_benign_sessions
from app.scenarios.runner import (
    ScenarioResult,
    ScenarioStep,
    record_step,
    reset_scenario_state,
    set_latest_s5_series,
)
from app.store import get_store
from app.stream import get_broadcaster

logger = logging.getLogger(__name__)

AGENT = "procurement-agent"
TRAINING_DAYS = 20  # σ from 10 days was unstable across seeds (0.0014–0.0072)
SESSIONS_PER_DAY = 50  # at 10/day the daily mix is noise-dominated (single-day spikes > 5σ trip CUSUM)
DRIFT_PER_DAY = 0.03  # SPEC §10: data-access breadth +3 %/day


def _run_day(rng: random.Random, day: int, drift_p: float) -> tuple[dict[str, float], int, Optional[tuple]]:
    """Run one simulated day of benign grammar sessions through the real gateway.

    With probability drift_p a session uses the grammar's broadest flow ("standard": catalog +
    supplier + purchase data). Every action and transition stays inside the learned baseline;
    only the mix shifts, which is the slow-drift threat model.
    Returns the day's observed tool distribution, its max event risk, and one sample call for the UI.
    """
    clock = get_clock()
    if hasattr(clock, "set_day"):
        clock.set_day(day)
    store = get_store()
    sessions = generate_benign_sessions(AGENT, SESSIONS_PER_DAY, seed=rng.randrange(2**31))
    counts: Counter[str] = Counter()
    max_risk = 0
    sample = None
    for calls in sessions:
        if rng.random() < drift_p:
            calls = _generate_procurement_session(rng, flow="standard")
        agent = ScriptedAgent(AGENT, think_time_s=120.0)  # ~2 min between calls: under the 30/min rate limit
        agent.start()
        for tool, args, purpose in calls:
            resp = agent.call(tool=tool, args=args, purpose=purpose)
            sample = sample or (agent, tool, args, purpose, resp)
        for ev in store.list_events(session_id=agent.session_id):
            counts[ev.tool] += 1
            # Per-event signal only: events where D6 contributes are the drift detector doing its job
            if not any(d.name == "drift_cusum" and d.score > 0 for d in ev.detector_results):
                max_risk = max(max_risk, ev.risk)
    total = sum(counts.values())
    return {t: c / total for t, c in counts.items()}, max_risk, sample


def _find_sustained_alarm_start(alarms: list[bool], min_consecutive: int = 3) -> Optional[int]:
    """Return the 1-indexed day where a run of >= min_consecutive alarmed days begins, or None."""
    consecutive = 0
    for idx, alarmed in enumerate(alarms):
        if alarmed:
            consecutive += 1
            if consecutive >= min_consecutive:
                return (idx - min_consecutive + 1) + 1
        else:
            consecutive = 0
    return None


def run_s5(
    reset: bool = True,
    step_delay_ms: int = 700,
    seed: Optional[int] = None,
) -> ScenarioResult:
    """Run Scenario 5: Multi-Day Slow Drift.

    20 benign training days fit μ0/κ/h; then 30 drift days. All traffic is real grammar sessions
    through the gateway; every action stays inside the contract and the learned baseline.
    Outputs series: {day, divergence, cusum, h, cusum_alarm, ewma_score, ewma_alarm, max_event_risk_without_d6}.
    """
    if reset:
        reset_scenario_state(seed=seed)

    scenario_seed = seed if seed is not None else get_settings().SCENARIO_SEED
    rng = random.Random(scenario_seed + 5)
    steps: list[ScenarioStep] = []
    step_idx = 1
    anchor = get_baseline().get_frozen_anchor(AGENT)

    # 1. Training days: benign traffic only -> fit μ0, κ = 0.5·std, h = 5·std (SPEC §6). Nothing is hand-set.
    train_dists = [_run_day(rng, -TRAINING_DAYS + i, drift_p=0.0)[0] for i in range(TRAINING_DAYS)]
    cusum = get_cusum_tracker(AGENT)
    cusum.fit_anchor([jensen_shannon_divergence(d, anchor) for d in train_dists])

    # EWMA comparator gets the same treatment: alarm when a day exceeds mean + 3·std of its training divergences
    ewma = EWMATracker()
    ewma.baseline = dict(anchor)
    ewma_train = [ewma.update(d) for d in train_dists]
    ewma_mu = statistics.fmean(ewma_train)
    ewma_threshold = ewma_mu + 3 * statistics.pstdev(ewma_train, ewma_mu)

    # 2. Monitored days: a share of sessions (0.03·day) adds one extra in-contract catalog sweep
    series: list[dict[str, Any]] = []
    alarm_day: Optional[int] = None
    watch_before_alarm = False
    for day in range(1, 31):
        day_dist, max_risk, sample = _run_day(rng, day, drift_p=min(1.0, DRIFT_PER_DAY * day))
        d_t = jensen_shannon_divergence(day_dist, anchor)
        s_t = cusum.update_day(d_t)
        d_ewma = ewma.update(day_dist)
        if cusum.is_alarm() and alarm_day is None:
            alarm_day = day
        if alarm_day is None and max_risk >= 30:
            watch_before_alarm = True
        series.append({
            "day": day,
            "divergence": round(d_t, 4),
            "cusum": round(s_t, 4),
            "h": round(cusum.h, 4),
            "cusum_alarm": cusum.is_alarm(),
            "ewma_score": round(d_ewma, 4),
            "ewma_alarm": d_ewma > ewma_threshold,
            "ewma_threshold": round(ewma_threshold, 4),
            "max_event_risk_without_d6": max_risk,
        })
        if day in (1, 5, 10, 13, 20, 30) and sample:
            agent, tool, args, purpose, resp = sample
            steps.append(record_step("s5", step_idx, agent, tool, args, purpose, resp, step_delay_ms))
            step_idx += 1

    set_latest_s5_series(
        series,
        h=round(cusum.h, 4),
        ewma_threshold=round(ewma_threshold, 4),
    )

    # SPEC §10 pass criteria:
    # 1. CUSUM raises a SUSTAINED alarm (≥ 3 consecutive alarmed days) between day 10 and day 25
    cusum_alarms = [e["cusum_alarm"] for e in series]
    cusum_sustained_start = _find_sustained_alarm_start(cusum_alarms, 3)
    cusum_sustained_ok = cusum_sustained_start is not None and (10 <= cusum_sustained_start <= 25)

    # 2. EWMA never sustains an alarm (no 3 consecutive alarmed days; single isolated blips allowed)
    ewma_alarms = [e["ewma_alarm"] for e in series]
    ewma_sustained_start = _find_sustained_alarm_start(ewma_alarms, 3)
    ewma_never_sustained = (ewma_sustained_start is None)

    # 3. No single event reaches WATCH before the CUSUM alarm
    passed = cusum_sustained_ok and ewma_never_sustained and not watch_before_alarm

    summary = (
        f"S5 Slow Drift: fitted μ0={cusum.mu0:.4f}, κ={cusum.kappa:.4f}, h={cusum.h:.4f} from {TRAINING_DAYS} training days. "
        f"CUSUM first alarm day {alarm_day}, sustained (≥3 consecutive) start day {cusum_sustained_start}. "
        f"EWMA alarms: {sum(ewma_alarms)} (sustained: {not ewma_never_sustained}, threshold {ewma_threshold:.4f}). "
        f"Events ≥ WATCH before alarm: {watch_before_alarm}."
    )

    result = ScenarioResult(
        id="s5",
        name="Slow Drift (CUSUM vs EWMA Baseline)",
        description="20 benign training days fit CUSUM; then 30 days where 3%/day more sessions use the broadest in-contract flow",
        steps=steps,
        expected="CUSUM raises sustained alarm (≥ 3 consecutive days) between day 10 and 25; EWMA never sustains an alarm; per-event detectors stay below WATCH before CUSUM alarm",
        passed=passed,
        alert_ids=[],
        capture_ids=[],
        summary=summary,
    )

    get_broadcaster().broadcast_sync(
        "scenario_done",
        {"scenario_id": "s5", "result": result.model_dump()},
    )

    return result
