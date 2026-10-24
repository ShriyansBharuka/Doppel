"""CLI runner for live Gemini agent with recording support per Prompt 4b Task 2."""

import argparse
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path

from app.agents.gemini_agent import GeminiStepRecord, run_gemini_agent

logger = logging.getLogger(__name__)

RECORDINGS_DIR = Path(__file__).resolve().parent.parent / "scenarios" / "recordings"


def format_step_printout(step: GeminiStepRecord) -> None:
    """Print readable step trace to console."""
    if step.model_text:
        print(f"\n[Step {step.step_num}] Model text:\n  {step.model_text}")
    if step.tool:
        print(f"\n[Step {step.step_num}] Tool Call: {step.tool}")
        print(f"  Sigil: {step.sigil_status} (args={step.args})")
        print(f"  Agent response: {step.agent_response}")
        print(
            f"  Doppel: decision={step.doppel_decision} | "
            f"risk={step.doppel_risk} | tier={step.doppel_tier}"
        )
        if step.alert_id:
            print(f"  Alert: {step.alert_id} | Top evidence: {step.top_evidence}")


def save_recording(result) -> Path:
    """Save transcript JSON to app/scenarios/recordings/."""
    RECORDINGS_DIR.mkdir(parents=True, exist_ok=True)
    clean_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    clean_model = result.model.replace("/", "_").replace(":", "_")
    filename = f"recording_{result.agent_id}_{clean_model}_{clean_ts}.json"
    filepath = RECORDINGS_DIR / filename

    transcript = {
        "model": result.model,
        "timestamp": result.timestamp,
        "agent_id": result.agent_id,
        "task": result.task,
        "system_prompt": result.system_prompt,
        "final_text": result.final_text,
        "completed": result.completed,
        "error": result.error,
        "messages": [s.model_dump() for s in result.steps],
    }

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(transcript, f, indent=2)

    logger.info("Saved live transcript to %s", filepath)
    return filepath


def main() -> None:
    parser = argparse.ArgumentParser(description="Run live Gemini agent against Doppel gateway")
    parser.add_argument("--agent", default="procurement-agent", help="Agent role ID to run")
    parser.add_argument("--task", default=None, help="Custom prompt / task description")
    parser.add_argument("--model", default=None, help="Gemini model override")
    parser.add_argument("--record", action="store_true", help="Record transcript JSON to scenarios/recordings/")
    args = parser.parse_args()

    print(f"=== Starting Live Gemini Agent ({args.agent}) ===")
    try:
        result = run_gemini_agent(
            agent_id=args.agent,
            task=args.task,
            model_override=args.model,
            step_callback=format_step_printout,
        )
    except Exception as exc:
        print(f"\n[ERROR] Live agent execution failed: {exc}")
        sys.exit(1)

    print("\n=== Agent Run Finished ===")
    if result.final_text:
        print(f"Final model answer:\n{result.final_text}")
    if result.error:
        print(f"Run ended with error: {result.error}")

    if args.record:
        saved_path = save_recording(result)
        print(f"\nTranscript recorded to: {saved_path}")


if __name__ == "__main__":
    main()
