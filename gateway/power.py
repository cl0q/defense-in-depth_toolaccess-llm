"""
Power measurement harness (Phase 3).

Uses NVML's integrated energy counter (mJ, monotonically increasing) to measure
GPU energy consumption around individual model calls. Because the H200 has a
single power domain for the whole GPU, energy is attributed temporally, not
per-process. All measurements must therefore run with concurrency=1 and warm
models (past the JIT spike).

Key design decisions:
  - Uses nvmlDeviceGetTotalEnergyConsumption() (millijoules, ~1 kHz hardware
    counter on H100/H200), NOT the instantaneous power sample — no polling loop.
  - Each measurement window is: Δenergy = energy_after − energy_before.
  - Appends a JSONL record to POWER_LOG_FILE so traces can be joined later.
  - A "role" label (victim/guard/attacker) is recorded per window so the
    analysis layer can separate model contributions.
  - Gracefully degrades: if pynvml is unavailable or the GPU counter fails,
    the context manager is a no-op and logs a warning once.

Environment variables:
  POWER_LOG_FILE    path to the JSONL log          (default: power_log.jsonl in cwd)
  POWER_GPU_INDEX   NVML GPU index to sample        (default: 0)
  POWER_ENABLED     set to "0" to disable           (default: 1, auto-disabled if no pynvml)
"""

import os
import json
import logging
import time
from contextlib import contextmanager
from typing import Optional

logger = logging.getLogger(__name__)

POWER_LOG_FILE: str = os.environ.get("POWER_LOG_FILE", "power_log.jsonl")
POWER_GPU_INDEX: int = int(os.environ.get("POWER_GPU_INDEX", "0"))
POWER_ENABLED: bool = os.environ.get("POWER_ENABLED", "1") == "1"

_nvml_handle = None
_nvml_ok: Optional[bool] = None  # None = not yet tried


def _init_nvml():
    global _nvml_handle, _nvml_ok
    if _nvml_ok is not None:
        return _nvml_ok
    if not POWER_ENABLED:
        _nvml_ok = False
        return False
    try:
        import pynvml  # type: ignore
        pynvml.nvmlInit()
        _nvml_handle = pynvml.nvmlDeviceGetHandleByIndex(POWER_GPU_INDEX)
        # Smoke-test: the counter must be supported.
        pynvml.nvmlDeviceGetTotalEnergyConsumption(_nvml_handle)
        _nvml_ok = True
        logger.info("Power measurement enabled (GPU %d, log=%s)", POWER_GPU_INDEX, POWER_LOG_FILE)
    except Exception as exc:
        logger.warning("Power measurement disabled: %s", exc)
        _nvml_ok = False
    return _nvml_ok


def _read_energy_mj() -> Optional[int]:
    """Return current total energy counter in millijoules, or None on error."""
    try:
        import pynvml  # type: ignore
        return pynvml.nvmlDeviceGetTotalEnergyConsumption(_nvml_handle)
    except Exception as exc:
        logger.warning("Energy read failed: %s", exc)
        return None


def _append_record(record: dict) -> None:
    try:
        with open(POWER_LOG_FILE, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
    except Exception as exc:
        logger.warning("Failed to write power log: %s", exc)


@contextmanager
def measure(role: str, trace_id: str = "", active_layers: Optional[list] = None):
    """
    Context manager that wraps a model call and records energy consumption.

    Usage:
        with measure("victim", trace_id=trace_id, active_layers=active_layers):
            result = call_victim_model(...)

    Args:
        role:          "victim" | "guard" | "attacker" (free string, used for grouping)
        trace_id:      gateway trace ID for joining with latency records
        active_layers: list of active defense layer names (provenance)

    Yields: nothing (measurements are written to POWER_LOG_FILE)
    """
    if not _init_nvml():
        yield
        return

    t_start = time.perf_counter()
    e_start = _read_energy_mj()

    try:
        yield
    finally:
        t_end = time.perf_counter()
        e_end = _read_energy_mj()

        if e_start is not None and e_end is not None:
            delta_mj = e_end - e_start
            duration_s = t_end - t_start
            record = {
                "trace_id": trace_id,
                "role": role,
                "active_layers": active_layers or [],
                "energy_mj": delta_mj,
                "duration_s": round(duration_s, 6),
                "timestamp": time.time(),
                "gpu_index": POWER_GPU_INDEX,
            }
            _append_record(record)
            logger.debug(
                "Power [role=%s trace=%s]: %.1f mJ  %.3f s",
                role, trace_id, delta_mj, duration_s,
            )
