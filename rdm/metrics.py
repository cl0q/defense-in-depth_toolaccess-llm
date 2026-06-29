"""
Metrics: host resources (psutil), GPU (pynvml) and attack energy (power_log).

All sampling is cheap and degrades gracefully: missing psutil/pynvml just blanks
the relevant panel. NVML reuses one handle and reads the integrated energy
counter, identical to gateway/power.py — no polling loop, ~zero overhead.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .discover import IDLE_BASELINE, RunContext


@dataclass
class Host:
    cpu: float = 0.0
    ram_pct: float = 0.0
    ram_used: float = 0.0
    ram_total: float = 0.0


@dataclass
class Gpu:
    ok: bool = False
    name: str = ""
    util: int = 0
    power_w: float = 0.0
    vram_used: float = 0.0
    vram_total: float = 0.0


@dataclass
class Energy:
    idle_w: Optional[float] = None
    total_wh: float = 0.0
    net_wh: float = 0.0
    calls: int = 0
    last_mj: float = 0.0
    per_layer: dict[str, float] = field(default_factory=dict)


_nvml = None
_handle = None


def _gpu_init() -> bool:
    global _nvml, _handle
    if _handle is not None:
        return True
    try:
        import pynvml  # type: ignore
        pynvml.nvmlInit()
        _handle = pynvml.nvmlDeviceGetHandleByIndex(0)
        _nvml = pynvml
        return True
    except Exception:
        return False


def host() -> Host:
    try:
        import psutil  # type: ignore
        vm = psutil.virtual_memory()
        return Host(cpu=psutil.cpu_percent(interval=None), ram_pct=vm.percent,
                    ram_used=vm.used / 2**30, ram_total=vm.total / 2**30)
    except Exception:
        return Host()


def gpu() -> Gpu:
    if not _gpu_init():
        return Gpu()
    try:
        n = _nvml.nvmlDeviceGetName(_handle)
        name = n.decode() if isinstance(n, bytes) else n
        u = _nvml.nvmlDeviceGetUtilizationRates(_handle)
        mem = _nvml.nvmlDeviceGetMemoryInfo(_handle)
        try:
            w = _nvml.nvmlDeviceGetPowerUsage(_handle) / 1000.0
        except Exception:
            w = 0.0
        return Gpu(ok=True, name=name, util=u.gpu, power_w=w,
                   vram_used=mem.used / 2**30, vram_total=mem.total / 2**30)
    except Exception:
        return Gpu()


def _idle_w() -> Optional[float]:
    try:
        for line in IDLE_BASELINE.read_text(encoding="utf-8").splitlines():
            r = json.loads(line)
            if r.get("type") == "idle_baseline" and r.get("duration_s", 0) > 0:
                return r["avg_power_w"]
    except Exception:
        pass
    return None


def energy(ctx: RunContext) -> Energy:
    """Sum per-call GPU energy from power_log.jsonl; net of idle baseline."""
    e = Energy(idle_w=_idle_w())
    if not ctx.run_dir:
        return e
    last = 0.0
    for pl in ctx.run_dir.glob("*/power_log.jsonl"):
        layer = pl.parent.name
        try:
            for line in pl.read_text(encoding="utf-8").splitlines():
                r = json.loads(line)
                mj = float(r.get("energy_mj", 0))
                dur = float(r.get("duration_s", 0))
                e.calls += 1
                e.total_wh += mj / 3.6e6
                net = mj - (e.idle_w * dur * 1000.0) if e.idle_w else mj
                e.net_wh += max(0.0, net) / 3.6e6
                e.per_layer[layer] = e.per_layer.get(layer, 0.0) + mj / 3.6e6
                last = mj
        except Exception:
            continue
    e.last_mj = last
    return e
