#!/usr/bin/env bash
# =============================================================================
# measure_idle_baseline.sh  —  record GPU idle power with all models resident
# -----------------------------------------------------------------------------
# Run this ONCE before any experiment, with all three vLLM servers warmed up
# (victim :8001, attacker :8002, guard :8003) but no inference happening.
# The resulting JSONL record is used in analysis to subtract idle consumption
# from per-call energy measurements, giving net inference energy.
#
# Recommended procedure:
#   1. Start all three vLLM servers (victim, attacker, guard) and wait for them
#      to finish warmup (watch logs until "Application startup complete").
#   2. Run this script: ./measure_idle_baseline.sh
#   3. Inspect idle_baseline.jsonl — you should see ~70–100 W idle.
#   4. Start the gateway and run experiments.
#
# Output: idle_baseline.jsonl  (one JSON record, appended)
#
# Environment variables:
#   IDLE_DURATION_S   how long to sample (default 30 s)
#   POWER_GPU_INDEX   NVML GPU index     (default 0)
#   IDLE_OUTPUT_FILE  output path        (default idle_baseline.jsonl)
# =============================================================================
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

duration="${IDLE_DURATION_S:-30}"
gpu_index="${POWER_GPU_INDEX:-0}"
output="${IDLE_OUTPUT_FILE:-$script_dir/idle_baseline.jsonl}"

echo "Measuring idle GPU baseline for ${duration}s on GPU ${gpu_index} ..."
echo "  (all models should be loaded but no inference in flight)"

python3 - <<PYEOF
import time, json, os

try:
    import pynvml
    pynvml.nvmlInit()
    handle = pynvml.nvmlDeviceGetHandleByIndex(${gpu_index})
    name = pynvml.nvmlDeviceGetName(handle).decode() if isinstance(
            pynvml.nvmlDeviceGetName(handle), bytes) else pynvml.nvmlDeviceGetName(handle)

    duration_s = float("${duration}")
    t_start = time.perf_counter()
    e_start = pynvml.nvmlDeviceGetTotalEnergyConsumption(handle)

    print(f"  energy counter start: {e_start} mJ")
    time.sleep(duration_s)

    t_end = time.perf_counter()
    e_end = pynvml.nvmlDeviceGetTotalEnergyConsumption(handle)

    delta_mj  = e_end - e_start
    actual_s  = t_end - t_start
    avg_w     = (delta_mj / 1000.0) / actual_s

    record = {
        "type": "idle_baseline",
        "gpu_index": ${gpu_index},
        "gpu_name": name,
        "duration_s": round(actual_s, 3),
        "energy_mj": delta_mj,
        "avg_power_w": round(avg_w, 2),
        "timestamp": time.time(),
    }
    print(f"  energy delta: {delta_mj} mJ  =>  avg idle power: {avg_w:.1f} W")

    with open("${output}", "a") as fh:
        fh.write(json.dumps(record) + "\n")
    print(f"  written to {os.path.abspath('${output}')}")

except Exception as e:
    print(f"ERROR: {e}")
    raise SystemExit(1)
PYEOF
