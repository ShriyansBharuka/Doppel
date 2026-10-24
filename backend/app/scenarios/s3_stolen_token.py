"""Scenario S3: Stolen Token Replay from Unauthorized Environment (SPEC §10)."""

import logging
from typing import Optional

from app.agents.scripted import ScriptedAgent
from app.clock import get_clock
from app.models import Decision, Tier
from app.scenarios.runner import (
    ScenarioResult,
    ScenarioStep,
    record_step,
    reset_scenario_state,
)
from app.store import get_store
from app.stream import get_broadcaster

logger = logging.getLogger(__name__)


def run_s3(
    reset: bool = True,
    step_delay_ms: int = 700,
    seed: Optional[int] = None,
) -> ScenarioResult:
    """Run Scenario 3: Stolen Token.

    A normal procurement session makes 2 calls. An attacker reuses the same token
    with a different fingerprint, no sigil, <50ms gap, calling purchase_request.create
    for 'Quickship Global' -> caught on that first call; real world state untouched.
    """
    if reset:
        reset_scenario_state(seed=seed)

    store = get_store()
    clock = get_clock()
    steps: list[ScenarioStep] = []

    # Legitimate procurement agent
    agent = ScriptedAgent("procurement-agent", runtime_fingerprint="fp-legit-procurement")
    agent.start()

    # Step 1: Normal catalog read
    r1 = agent.call(
        tool="doc.read",
        args={"path": "/procurement/catalog/products.csv"},
        purpose="Reviewing catalog inventory",
    )
    steps.append(record_step("s3", 1, agent, "doc.read", {"path": "/procurement/catalog/products.csv"}, "Reviewing catalog inventory", r1, step_delay_ms))

    # Step 2: Normal catalog search
    r2 = agent.call(
        tool="supplier_catalog.search",
        args={"query": "office equipment"},
        purpose="Searching office equipment suppliers",
    )
    steps.append(record_step("s3", 2, agent, "supplier_catalog.search", {"query": "office equipment"}, "Searching suppliers", r2, step_delay_ms))

    # Attacker reuses token: advance clock by 0.02s (<50 ms gap), new fingerprint, NO sigil
    if hasattr(clock, "advance"):
        clock.advance(0.02)

    stolen_token = agent.token
    session_id = agent.session_id

    # Create attacker agent using the stolen token and new environment
    attacker = ScriptedAgent(
        agent_id="procurement-agent",
        runtime_fingerprint="fp-attacker-cloud-vm",
        think_time_s=0.0,  # the 0.02 s gap above is the attack's own timing
    )
    attacker.session_id = session_id
    attacker.token = stolen_token
    attacker.sigil = None  # Attacker does NOT possess the private per-session sigil

    # Step 3: Attacker attempts unauthorized purchase_request
    r3 = attacker.call(
        tool="purchase_request.create",
        args={"vendor": "Quickship Global", "items": ["100x High-End Laptops"], "amount": 185000},
        purpose="Procurement order fulfillment",
        sigil=None,
        runtime_fingerprint="fp-attacker-cloud-vm",
        token=stolen_token,
    )
    steps.append(record_step("s3", 3, attacker, "purchase_request.create", {"vendor": "Quickship Global", "items": ["100x High-End Laptops"], "amount": 185000}, "Procurement order fulfillment", r3, step_delay_ms))

    # Evaluation & Checks
    session = store.get_session(session_id)
    events = store.list_events(session_id=session_id)
    attacker_event = events[-1] if events else None

    alerts = store.list_alerts(session_id=session_id)
    real_requests = store.get_purchase_requests()

    passed = (
        session is not None
        and attacker_event is not None
        and attacker_event.decision in (Decision.sinkhole, Decision.hold, Decision.block)
        and session.tier in (Tier.WATCH, Tier.SHRINK, Tier.ISOLATE)
        and len(alerts) >= 1
        and len(real_requests) == 0  # Real purchase request store was NEVER touched
    )

    alert_ids = [a.alert_id for a in alerts]
    summary = (
        f"S3 Stolen Token: Attacker call caught with decision={attacker_event.decision.value if attacker_event else 'None'} "
        f"(event_risk={attacker_event.risk if attacker_event else 0}, tier={session.tier.value if session else 'None'}). "
        f"Real purchase requests created: {len(real_requests)}."
    )

    result = ScenarioResult(
        id="s3",
        name="Stolen Token Replay (Context & Sigil Defense)",
        description="Token reused from new fingerprint without sigil <50ms apart for purchase_request; caught immediately",
        steps=steps,
        expected="Caught on first call (risk >= 60), alert created, real world purchase requests empty",
        passed=passed,
        alert_ids=alert_ids,
        capture_ids=[],
        summary=summary,
    )

    get_broadcaster().broadcast_sync(
        "scenario_done",
        {"scenario_id": "s3", "result": result.model_dump()},
    )

    return result
