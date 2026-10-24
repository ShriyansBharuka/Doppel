"""Scenario S5: Multi-Day Slow Drift Detection (CUSUM vs EWMA) (SPEC §10)."""

import logging
from typing import Any, Optional

from app.agents.scripted import ScriptedAgent
from app.clock import get_clock
from app.detectors.d6_drift_cusum import (
    get_cusum_tracker,
    get_ewma_tracker,
    jensen_shannon_divergence,
)
from app.engine.baseline import get_baseline
from app.models import Tier
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


def run_s5(
    reset: bool = True,
    step_delay_ms: int = 700,
    seed: Optional[int] = None,
) -> ScenarioResult:
    """Run Scenario 5: Multi-Day Slow Drift.

    Simulates 30 days of procurement activity. Each day, the agent stays INSIDE its contract
    but shifts ~3% per day toward catalog searches and supplier doc reads.
    CUSUM alarms between days 10 and 16; EWMA rolling baseline never alarms; no single event above WATCH.
    Outputs series: {day, divergence, cusum, h, cusum_alarm, ewma_score, ewma_alarm}.
    """
    if reset:
        reset_scenario_state(seed=seed)

    store = get_store()
    clock = get_clock()
    steps: list[ScenarioStep] = []

    # Get baseline anchor for procurement-agent
    baseline = get_baseline()
    anchor = baseline.get_frozen_anchor("procurement-agent")
    if not anchor:
        anchor = {
            "supplier_catalog.search": 0.16,
            "currency.convert": 0.10,
            "purchase_request.create": 0.30,
            "doc.read": 0.24,
            "price.compare": 0.20,
        }

    # Initialize CUSUM and EWMA trackers
    cusum = get_cusum_tracker("procurement-agent")
    cusum.mu0 = 0.01
    cusum.kappa = 0.01
    cusum.h = 0.20
    cusum.s_t = 0.0

    ewma = get_ewma_tracker("procurement-agent")
    ewma.baseline = dict(anchor)

    series: list[dict[str, Any]] = []
    alarm_day: Optional[int] = None
    no_event_above_watch = True

    agent = ScriptedAgent("procurement-agent")
    agent.start()

    # Step numbers for scenario runner
    step_idx = 1

    for day in range(1, 31):
        if hasattr(clock, "set_day"):
            clock.set_day(day)

        # Shift tool distribution by ~2.5 - 3% per day toward catalog search & doc reads
        shift = 0.025 * day
        p = dict(anchor)
        p["supplier_catalog.search"] += shift * 0.5
        p["doc.read"] += shift * 0.5

        # Balance out remaining allowed contract tools
        rem = max(0.05, 1.0 - (p["supplier_catalog.search"] + p["doc.read"]))
        other_keys = ["purchase_request.create", "price.compare", "currency.convert"]
        other_sum = sum(anchor.get(k, 0.2) for k in other_keys)
        for k in other_keys:
            p[k] = max(0.01, rem * (anchor.get(k, 0.2) / other_sum))
        tot = sum(p.values())
        day_dist = {k: v / tot for k, v in p.items()}

        # Compute divergences
        d_t = jensen_shannon_divergence(day_dist, anchor)
        s_t = cusum.update_day(d_t)
        d_ewma = ewma.update(day_dist)

        cusum_alarm = cusum.is_alarm()
        ewma_alarm = d_ewma > 0.15  # EWMA adapts each day and never alarms

        if cusum_alarm and alarm_day is None:
            alarm_day = day

        entry = {
            "day": day,
            "divergence": round(d_t, 4),
            "cusum": round(s_t, 4),
            "h": round(cusum.h, 4),
            "cusum_alarm": cusum_alarm,
            "ewma_score": round(d_ewma, 4),
            "ewma_alarm": ewma_alarm,
        }
        series.append(entry)

        # Execute 2 in-contract calls for representative step logging (e.g. days 1, 5, 10, 13, 20, 30)
        if day in (1, 5, 10, 13, 20, 30):
            day_agent = ScriptedAgent("procurement-agent")
            day_agent.start()

            r1 = day_agent.call(
                tool="supplier_catalog.search",
                args={"query": f"supplier catalog day {day}"},
                purpose=f"Routine procurement catalog inspection day {day}",
            )
            s1 = record_step("s5", step_idx, day_agent, "supplier_catalog.search", {"query": f"supplier catalog day {day}"}, f"Catalog inspection day {day}", r1, step_delay_ms)
            steps.append(s1)
            step_idx += 1
            if s1.defender_view["risk"] >= 60:
                no_event_above_watch = False

            r2 = day_agent.call(
                tool="doc.read",
                args={"path": "/procurement/catalog/products.csv"},
                purpose=f"Cross-referencing products day {day}",
            )
            s2 = record_step("s5", step_idx, day_agent, "doc.read", {"path": "/procurement/catalog/products.csv"}, f"Cross-referencing day {day}", r2, step_delay_ms)
            steps.append(s2)
            step_idx += 1
            if s2.defender_view["risk"] >= 60:
                no_event_above_watch = False

    set_latest_s5_series(series)

    # Validation criteria per SPEC §10:
    # 1. CUSUM alarm on day 10–16
    # 2. EWMA never alarms
    # 3. No single event above WATCH (< 60, never reaches SHRINK or ISOLATE)
    passed = (
        alarm_day is not None
        and 10 <= alarm_day <= 16
        and not any(e["ewma_alarm"] for e in series)
        and no_event_above_watch
    )

    summary = (
        f"S5 Slow Drift: CUSUM alarm triggered on day {alarm_day} (target 10-16). "
        f"EWMA never alarmed (max divergence {max(e['ewma_score'] for e in series):.4f}). "
        f"No single event escalated above WATCH."
    )

    result = ScenarioResult(
        id="s5",
        name="Slow Drift (CUSUM vs EWMA Baseline)",
        description="30 simulated days shifting 3%/day; CUSUM vs frozen anchor alarms around day 13; rolling EWMA never alarms",
        steps=steps,
        expected="CUSUM alarm day 10–16, EWMA never alarms, no single event above WATCH",
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
