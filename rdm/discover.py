"""
Discovery: find the active sweep, its artifact directory, log files and PIDs.

Everything here is best-effort and read-only. We never touch the gateway or the
sweep processes; we only look at the files they already write and the process
table. On non-Linux or when nothing is running, callers fall back to "latest run
on disk" so the UI is still useful for inspecting finished sweeps.
"""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
ARTIFACT_ROOT = REPO_ROOT / "analysis" / "artifacts" / "pyrit"
SWEEP_LOG = REPO_ROOT / "sweep_full.log"
IDLE_BASELINE = REPO_ROOT / "idle_baseline.jsonl"

LAYER_ORDER = ["D0", "DA", "DB", "DC-a", "DC-b", "DC-c", "D++", "DT"]

# Ports owned by the stack (from run_pyrit_layers.sh / start_*.sh).
PORT_ROLES = {8000: "gateway", 8001: "victim", 8002: "attacker", 8003: "guard"}


@dataclass
class Manifest:
    run_id: str = ""
    strategies: list[str] = field(default_factory=list)
    goals: str = "all"
    layers: list[str] = field(default_factory=list)
    max_turns: int = 0
    attacker_model: str = ""

    @classmethod
    def load(cls, path: Path) -> "Manifest":
        m = cls()
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                if "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k, v = k.strip(), v.strip()
                if k == "run_id":
                    m.run_id = v
                elif k == "strategies":
                    m.strategies = [s for s in v.split(",") if s]
                elif k == "goals":
                    m.goals = v
                elif k == "layers":
                    m.layers = [s for s in v.split(",") if s]
                elif k == "max_turns":
                    m.max_turns = int(v or 0)
                elif k == "attacker_model":
                    m.attacker_model = v
        except Exception:
            pass
        return m


@dataclass
class RunContext:
    run_dir: Optional[Path]
    manifest: Manifest
    sweep_pid: Optional[int] = None
    live: bool = False

    @property
    def run_id(self) -> str:
        return self.manifest.run_id or (self.run_dir.name if self.run_dir else "—")

    @property
    def start_epoch(self) -> Optional[float]:
        """Sweep start time parsed from the run-id (YYYYMMDDThhmmssZ)."""
        rid = self.run_id
        try:
            t = time.strptime(rid, "%Y%m%dT%H%M%SZ")
            return time.mktime(t) - time.timezone
        except Exception:
            if self.run_dir:
                return self.run_dir.stat().st_mtime
            return None


def latest_run_dir() -> Optional[Path]:
    """Newest run-id directory by mtime, or None."""
    if not ARTIFACT_ROOT.is_dir():
        return None
    runs = [p for p in ARTIFACT_ROOT.iterdir() if p.is_dir()]
    if not runs:
        return None
    return max(runs, key=lambda p: p.stat().st_mtime)


def find_sweep_pid() -> Optional[int]:
    """PID printed by run_full_suite.sh ('[sweep] pid=...'), if still alive."""
    pid = None
    try:
        txt = SWEEP_LOG.read_text(encoding="utf-8", errors="replace")
        for m in re.finditer(r"\[sweep\] pid=(\d+)", txt):
            pid = int(m.group(1))
    except Exception:
        return None
    if pid and _alive(pid):
        return pid
    return None


def _alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        import psutil  # type: ignore

        return psutil.pid_exists(pid)
    except Exception:
        try:
            os.kill(pid, 0)
            return True
        except Exception:
            return False


def discover() -> RunContext:
    """Resolve the run to monitor: prefer a live sweep, else the latest on disk."""
    rd = latest_run_dir()
    manifest = Manifest.load(rd / "manifest.txt") if rd else Manifest()
    if rd and not manifest.run_id:
        manifest.run_id = rd.name
    pid = find_sweep_pid()
    live = pid is not None or _recently_modified(rd)
    return RunContext(run_dir=rd, manifest=manifest, sweep_pid=pid, live=live)


def _recently_modified(rd: Optional[Path], window_s: int = 90) -> bool:
    if not rd:
        return False
    try:
        for p in rd.rglob("*.log"):
            if time.time() - p.stat().st_mtime < window_s:
                return True
    except Exception:
        pass
    return False


def stack_processes() -> dict[str, dict]:
    """Map role -> {pid,name,cmd} for stack ports we can see. Best-effort."""
    out: dict[str, dict] = {}
    try:
        import psutil  # type: ignore
    except Exception:
        return out
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.status != psutil.CONN_LISTEN or not c.laddr or not c.pid:
                continue
            role = PORT_ROLES.get(c.laddr.port)
            if not role or role in out:
                continue
            try:
                p = psutil.Process(c.pid)
                out[role] = {"pid": c.pid, "name": p.name(),
                             "cmd": " ".join(p.cmdline()[:3])}
            except Exception:
                out[role] = {"pid": c.pid, "name": "?", "cmd": ""}
    except Exception:
        pass
    return out
