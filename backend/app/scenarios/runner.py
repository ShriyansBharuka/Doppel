"""Scenario runner and step execution engine per SPEC §10 / Prompt 4a Task 2."""

from datetime import datetime, timezone
import logging
import time
from typing import Any, Callable, Optional
from pydantic import BaseModel, Field

from app.agents.scripted import ScriptedAgent
from app.clock import SimClock, set_clock
from app.config import get_settings
from app.contracts.loader import load_contracts
from app.detectors.d6_drift_cusum import reset_drift_trackers
from app.engine.baseline import init_baseline
from app.ids import new_id, set_seed
from app.models import Decision, Event
from app.store import get_store
from app.stream import get_broadcaster
from app.world.files import clear_dynamic_watermarks, init_world_files
from app.world.tools import init_tools, pin_hashes

logger = logging.getLogger(__name__)


class ScenarioStep(BaseModel):
    """Execution step containing both the agent's view and defender's view for split-screen display."""

    step_number: int
    agent_id: str
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    purpose: str = ""
    agent_view: dict[str, Any] = Field(default_factory=dict)
    defender_view: dict[str, Any] = Field(default_factory=dict)


class ScenarioResult(BaseModel):
    """Result of running a scripted scenario."""

    id: str
    name: str
    description: str
    steps: list[ScenarioStep] = Field(default_factory=list)
    expected: str
    passed: bool
    alert_ids: list[str] = Field(default_factory=list)
    capture_ids: list[str] = Field(default_factory=list)
    summary: str


# Global storage for background runs and S5 day series
_scenario_runs: dict[str, ScenarioResult] = {}
_latest_s5_series: list[dict[str, Any]] = []


def get_scenario_run(run_id: str) -> Optional[ScenarioResult]:
    """Retrieve run result by ID."""
    return _scenario_runs.get(run_id)


def save_scenario_run(run_id: str, result: ScenarioResult) -> None:
    """Store run result by ID."""
    _scenario_runs[run_id] = result


def get_latest_s5_series() -> list[dict[str, Any]]:
    """Retrieve the latest S5 drift simulation day series."""
    return list(_latest_s5_series)


def set_latest_s5_series(series: list[dict[str, Any]]) -> None:
    """Save latest S5 drift simulation day series."""
    global _latest_s5_series
    _latest_s5_series = list(series)


def reset_scenario_state(seed: Optional[int] = None) -> None:
    """Reset all module states, clocks, IDs, world files, and contracts for deterministic runs."""
    settings = get_settings()
    scenario_seed = seed if seed is not None else settings.SCENARIO_SEED

    store = get_store()
    store.reset()
    clear_dynamic_watermarks()
    reset_drift_trackers()
    set_seed(scenario_seed)

    # Initialize SimClock at anchor time
    sim_clock = SimClock(datetime(2026, 1, 1, 9, 0, 0, tzinfo=timezone.utc))
    set_clock(sim_clock)

    init_world_files(scenario_seed)
    init_tools()
    pin_hashes(store)

    contracts = load_contracts()
    for contract in contracts.values():
        store.save_contract(contract)

    init_baseline(scenario_seed)
    logger.info("Reset scenario environment with seed=%d", scenario_seed)


def record_step(
    scenario_id: str,
    step_number: int,
    agent: ScriptedAgent,
    tool: str,
    args: dict[str, Any],
    purpose: str,
    response: dict[str, Any],
    step_delay_ms: int = 0,
) -> ScenarioStep:
    """Capture dual agent_view and defender_view for the executed call, delay, and broadcast."""
    store = get_store()
    session = store.get_session(agent.session_id) if agent.session_id else None

    # Retrieve the event recorded for this call
    events = store.list_events(session_id=agent.session_id) if agent.session_id else []
    latest_event: Optional[Event] = events[-1] if events else None

    # Build Agent View: strictly what the agent received back
    agent_view = {
        "status": response.get("status"),
        "result": response.get("result"),
        "new_token": response.get("new_token"),
    }

    # Build Defender View: decision, risk, tier, top evidence, alert_id, sinkhole_capture_id
    top_evidence: list[str] = []
    decision_str = "unknown"
    event_risk = 0
    tier_str = "ALLOW"
    if latest_event:
        decision_str = latest_event.decision.value
        event_risk = latest_event.risk
        tier_str = latest_event.tier.value
        for d in sorted(latest_event.detector_results, key=lambda x: x.score, reverse=True):
            if d.score > 0 and d.evidence:
                top_evidence.extend(d.evidence)

    # Find sinkhole capture if call was sinkholed
    sinkhole_capture_id: Optional[str] = None
    if agent.session_id and decision_str == "sinkhole":
        captures = store.list_sinkhole_captures(session_id=agent.session_id)
        if captures:
            sinkhole_capture_id = captures[-1].capture_id

    defender_view = {
        "decision": decision_str,
        "risk": event_risk,
        "session_risk": session.risk if session else event_risk,
        "tier": tier_str,
        "top_evidence": top_evidence[:3],
        "alert_id": session.alert_id if session else None,
        "sinkhole_capture_id": sinkhole_capture_id,
        "taint_labels": [l.value for l in session.taint_labels] if session else [],
    }

    step = ScenarioStep(
        step_number=step_number,
        agent_id=agent.agent_id,
        tool=tool,
        args=args,
        purpose=purpose,
        agent_view=agent_view,
        defender_view=defender_view,
    )

    # Broadcast step on WebSocket live stream
    get_broadcaster().broadcast_sync(
        "scenario_step",
        {"scenario_id": scenario_id, "step": step.model_dump()},
    )

    # UI pacing delay
    if step_delay_ms > 0:
        time.sleep(step_delay_ms / 1000.0)

    return step
