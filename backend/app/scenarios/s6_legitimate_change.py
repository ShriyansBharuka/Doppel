"""Scenario S6: Legitimate Evolution via Signed Change Ticket (SPEC §10)."""

import logging
from typing import Optional

from app.agents.scripted import ScriptedAgent
from app.config import get_settings
from app.contracts.sign import sign_contract
from app.engine.baseline import get_baseline
from app.scenarios.runner import (
    ScenarioResult,
    ScenarioStep,
    record_step,
    reset_scenario_state,
)
from app.store import get_store
from app.stream import get_broadcaster

logger = logging.getLogger(__name__)


def run_s6(
    reset: bool = True,
    step_delay_ms: int = 700,
    seed: Optional[int] = None,
) -> ScenarioResult:
    """Run Scenario 6: Legitimate Change.

    Part A: Agent uses quote.request without a change ticket -> WATCH/SHRINK alert.
    Part B: Reset; issue contract v2 at runtime with quote.request, signed with existing sign function;
    baseline marks tool and transitions as declared-known and re-captures frozen anchor;
    agent uses quote.request -> session risk < 30, no alert.
    """
    settings = get_settings()
    store = get_store()
    steps: list[ScenarioStep] = []

    # =========================================================
    # Part A: Without change ticket -> Alert
    # =========================================================
    if reset:
        reset_scenario_state(seed=seed)

    agent_a = ScriptedAgent("procurement-agent")
    agent_a.start()

    # Step 1: Normal catalog read
    r1 = agent_a.call(
        tool="doc.read",
        args={"path": "/procurement/catalog/products.csv"},
        purpose="Reviewing catalog items before quoting",
    )
    steps.append(record_step("s6", 1, agent_a, "doc.read", {"path": "/procurement/catalog/products.csv"}, "Reviewing catalog", r1, step_delay_ms))

    # Step 2: Uses unapproved tool quote.request without ticket
    r2 = agent_a.call(
        tool="quote.request",
        args={"supplier": "Acme Corp", "items": ["Industrial Fasteners", "Safety Helmets"]},
        purpose="Requesting supplier quote via new tool",
    )
    steps.append(record_step("s6", 2, agent_a, "quote.request", {"supplier": "Acme Corp", "items": ["Industrial Fasteners", "Safety Helmets"]}, "Requesting supplier quote without ticket", r2, step_delay_ms))

    session_a = store.get_session(agent_a.session_id)
    alerts_a = store.list_alerts(session_id=agent_a.session_id)
    part_a_alerted = len(alerts_a) >= 1 and session_a is not None and session_a.risk >= 30

    # =========================================================
    # Part B: With signed Change Ticket v2 -> Allowed, no alert
    # =========================================================
    # Reset world per SPEC §10
    reset_scenario_state(seed=seed)

    # 1. Issue Contract v2 dynamically signed at runtime (DO NOT write to disk)
    contract_v1 = store.get_contract("procurement-agent")
    if not contract_v1:
        raise ValueError("procurement-agent contract not found in store")

    new_tools = list(contract_v1.allowed_tools)
    if "quote.request" not in new_tools:
        new_tools.append("quote.request")

    contract_v2 = contract_v1.model_copy(update={
        "version": 2,
        "allowed_tools": new_tools,
    })
    contract_v2.signature = sign_contract(contract_v2, settings.DOPPEL_SECRET)
    store.save_contract(contract_v2)

    # 2. Update baseline: mark quote.request and its transitions as declared-known and re-capture frozen anchor
    baseline = get_baseline()
    baseline.apply_change_ticket(
        agent_id="procurement-agent",
        new_tool="quote.request",
        contract_tools=contract_v2.allowed_tools,
    )

    # 3. Agent executes quote.request under verified contract v2
    agent_b = ScriptedAgent("procurement-agent")
    agent_b.start()

    # Step 3: Normal catalog read under contract v2
    r3 = agent_b.call(
        tool="doc.read",
        args={"path": "/procurement/catalog/products.csv"},
        purpose="Reviewing catalog items under contract v2",
    )
    steps.append(record_step("s6", 3, agent_b, "doc.read", {"path": "/procurement/catalog/products.csv"}, "Reviewing catalog under contract v2", r3, step_delay_ms))

    # Step 4: Approved quote.request under contract v2
    r4 = agent_b.call(
        tool="quote.request",
        args={"supplier": "Acme Corp", "items": ["Industrial Fasteners", "Safety Helmets"]},
        purpose="Requesting supplier quote via declared tool",
    )
    steps.append(record_step("s6", 4, agent_b, "quote.request", {"supplier": "Acme Corp", "items": ["Industrial Fasteners", "Safety Helmets"]}, "Requesting supplier quote via declared tool", r4, step_delay_ms))

    session_b = store.get_session(agent_b.session_id)
    alerts_b = store.list_alerts(session_id=agent_b.session_id)
    part_b_clean = session_b is not None and session_b.risk < 30 and len(alerts_b) == 0

    passed = part_a_alerted and part_b_clean

    alert_ids = [a.alert_id for a in alerts_a]
    summary = (
        f"S6 Legitimate Change: Part A alerted as expected (risk={session_a.risk if session_a else 0}, alerts={len(alerts_a)}). "
        f"Part B clean with signed Change Ticket v2 (risk={session_b.risk if session_b else 0}, alerts={len(alerts_b)})."
    )

    result = ScenarioResult(
        id="s6",
        name="Legitimate Evolution (Signed Change Ticket)",
        description="quote.request without change ticket triggers alert; contract v2 signed at runtime allows tool with risk < 30",
        expected="Part A produces WATCH alert, Part B with signed contract v2 stays risk < 30 with no alert",
        passed=passed,
        alert_ids=alert_ids,
        capture_ids=[],
        summary=summary,
    )

    get_broadcaster().broadcast_sync(
        "scenario_done",
        {"scenario_id": "s6", "result": result.model_dump()},
    )

    return result
