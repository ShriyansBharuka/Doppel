"""Run the full campaign matrix: variants 1-3 on gemini-3.5-flash-lite, plus gemini-3.1-flash-lite."""

import subprocess
import sys
import time

runs_to_execute = [
    ("gemini-3.5-flash-lite", 1, 10),
    ("gemini-3.5-flash-lite", 2, 10),
    ("gemini-3.5-flash-lite", 3, 10),
    ("gemini-3.1-flash-lite", 1, 10),
]

for model, variant, count in runs_to_execute:
    print(f"\n=======================================================")
    print(f"Launching Batch: Model={model}, Variant={variant}, Runs={count}")
    print(f"=======================================================")
    cmd = [
        sys.executable,
        "-m",
        "app.agents.run_live",
        "--agent",
        "procurement-agent",
        "--model",
        model,
        "--injection-variant",
        str(variant),
        "--runs",
        str(count),
        "--record",
    ]
    ret = subprocess.run(cmd)
    if ret.returncode != 0:
        print(f"Batch failed with returncode {ret.returncode}")
    time.sleep(3.0)

print("\nAll campaign batches finished.")
