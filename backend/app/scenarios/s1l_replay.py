"""Scenario S1L: Deterministic live Gemini replay per SPEC §10 / Prompt 4b Task 2."""

import json
import logging
from pathlib import Path
from typing import Any, Optional

from app.agents.scripted import ScriptedAgent
from app.scenarios.runner import (
    ScenarioResult,
    ScenarioStep,
    record_step,
    reset_scenario_state,
)
from app.store import get_store

logger = logging.getLogger(__name__)

RECORDINGS_DIR = Path(__file__).resolve().parent / "recordings"


def get_latest_recording() -> Optional[dict[str, Any]]:
    """Return parsed content of the most recent recording in recordings/ directory."""
    if not RECORDINGS_DIR.exists():
        return None

    json_files = sorted(RECORDINGS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not json_files:
        return None

    try:
        with open(json_files[0], "r", encoding="utf-8") as f:
            data = json.load(f)
            data["_filepath"] = str(json_files[0])
            return data
    except Exception as exc:
        logger.warning("Failed to load recording from %s: %s", json_files[0], exc)
        return None


def get_latest_recording_meta() -> Optional[dict[str, str]]:
    """Return model and date of latest recording, or None if unavailable."""
    rec = get_latest_recording()
    if not rec:
        return None
    return {
        "model": rec.get("model", "gemini"),
        "date": rec.get("timestamp", ""),
    }


def run_s1l(
    reset: bool = True,
    step_delay_ms: int = 0,
    seed: Optional[int] = 42,
) -> ScenarioResult:
    """Replay latest Gemini live recording through the gateway pipeline in a fresh session."""
    recording = get_latest_recording()
    if not recording:
        return ScenarioResult(
            id="s1l",
            name="Live Gemini Replay (S1L)",
            description="Replay of a real Gemini session. Unavailable: no recording exists in app/scenarios/recordings/",
            steps=[],
            expected="Unavailable (no recording found)",
            passed=False,
            summary="S1L unavailable: No recorded live Gemini transcripts found in app/scenarios/recordings/",
        )

    if reset:
        reset_scenario_state(seed=seed)

    store = get_store()
    agent_id = recording.get("agent_id", "procurement-agent")
    model = recording.get("model", "gemini")
    recorded_date = recording.get("timestamp", "unknown")

    # Start fresh session for the agent
    agent = ScriptedAgent(
        agent_id=agent_id,
        runtime_fingerprint=f"gemini-replay-{model}",
    )
    agent.start()
    session_id = agent.session_id or ""

    messages = recording.get("messages", [])
    steps: list[ScenarioStep] = []
    step_index = 0
    mismatches: list[str] = []

    for msg in messages:
        tool_name = msg.get("tool")
        if not tool_name:
            continue

        step_index += 1
        args = msg.get("args", {})
        # Recordings store only the status, never the value. Unknown status is replayed as missing (strict).
        sigil_status = msg.get("sigil_status", "missing")
        purpose = str(args.get("purpose", msg.get("purpose", "")))

        # Preserve model's sigil behavior
        if sigil_status == "correct":
            sent_sigil = agent.sigil
        elif sigil_status == "missing":
            sent_sigil = ""
        else:
            sent_sigil = (agent.sigil or "") + "_altered"

        # Parameters without harness metadata
        exec_params = {k: v for k, v in args.items() if k not in ("sigil", "purpose")}

        try:
            resp = agent.call(
                tool=tool_name,
                args=exec_params,
                purpose=purpose,
                sigil=sent_sigil,
            )
        except Exception as exc:
            resp = {"error": str(exc), "status": "blocked"}
        recorded_status = (msg.get("agent_response") or {}).get("status")
        if recorded_status is not None and recorded_status != resp.get("status"):
            mismatches.append(f"step {step_index} {tool_name}: recorded '{recorded_status}', replayed '{resp.get('status')}'")

        step = record_step(
            scenario_id="s1l",
            step_number=step_index,
            agent=agent,
            tool=tool_name,
            args=exec_params,
            purpose=purpose,
            response=resp,
            step_delay_ms=step_delay_ms,
        )
        steps.append(step)

    alert = store.get_session_alert(session_id)
    alert_ids = [alert.alert_id] if alert else []
    captures = store.list_sinkhole_captures(session_id=session_id)
    capture_ids = [c.capture_id for c in captures]

    summary = (
        f"Replayed {step_index} recorded steps from {model} ({recorded_date}). "
        f"Alerts: {len(alert_ids)}, Sinkhole captures: {len(capture_ids)}. "
        f"Agent-visible status mismatches vs recording: {mismatches or 'none'}"
    )

    return ScenarioResult(
        id="s1l",
        name="Live Gemini Replay (S1L)",
        description=f"Deterministic replay recorded from a live {model} run on {recorded_date}",
        steps=steps,
        expected="Every recorded call replays through the gateway with the same agent-visible status",
        passed=step_index > 0 and not mismatches,
        alert_ids=alert_ids,
        capture_ids=capture_ids,
        summary=summary,
    )
