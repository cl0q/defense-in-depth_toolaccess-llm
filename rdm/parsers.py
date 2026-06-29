"""
Parsers: turn the sweep's log/artifact files into structured state for the UI.

Pure stdlib, no LLM, no network. Designed to be cheap to call ~1×/sec:
- results JSONs are mtime-cached, so we only re-read changed files
- run.log / sweep_full.log are read tail-only
- pyrit.db (optional) is opened read-only/immutable for full transcripts
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .discover import LAYER_ORDER, SWEEP_LOG, RunContext

# ── run.log markers ────────────────────────────────────────────────────────
_RUN = re.compile(r"\u25b6\s*\[(\d+)/(\d+)\]\s*running\s+(\S+)\s*(.*)")  # ▶ [i/n]
_VERDICT = re.compile(r"(LEAK|BLOCKED)\s*\u00b7\s*(\d+)\s*turns?\s*\u00b7\s*role=(\w+)")
_LAYER_HDR = re.compile(r"Running PyRIT (\w[\w-]*) for layer ([\w+-]+)")
_GOAL = re.compile(r"\b(G-[A-Z]\d)\b")


@dataclass
class Cell:
    goal: str
    leak: bool
    turns: int
    role: str = ""


@dataclass
class Pair:
    strategy: str
    layer: str
    cells: list[Cell] = field(default_factory=list)
    done: bool = False

    @property
    def leaks(self) -> int:
        return sum(1 for c in self.cells if c.leak)


@dataclass
class Turn:
    n: int
    prompt: str
    response: str
    flag: bool = False


@dataclass
class Live:
    layer: str = ""
    strategy: str = ""
    goal: str = ""
    idx: int = 0
    total: int = 0
    verdict: str = ""
    turns: list[Turn] = field(default_factory=list)


class State:
    """All parsed run state. Re-reads only changed files on refresh()."""

    def __init__(self, ctx: RunContext):
        self.ctx = ctx
        self.pairs: dict[tuple[str, str], Pair] = {}
        self.live = Live()
        self._mtimes: dict[Path, float] = {}

    # -- completed pairs -----------------------------------------------------
    def refresh_results(self) -> None:
        rd = self.ctx.run_dir
        if not rd:
            return
        for jf in rd.glob("*/*/pyrit.results.json"):
            mt = _mtime(jf)
            if self._mtimes.get(jf) == mt:
                continue
            self._mtimes[jf] = mt
            try:
                data = json.loads(jf.read_text(encoding="utf-8"))
            except Exception:
                continue
            cells = []
            for r in data.get("results", []):
                cells.append(Cell(
                    goal=r.get("tags", {}).get("goal", "?"),
                    leak=bool(r.get("gradingResult", {}).get("pass")),
                    turns=int(r.get("metadata", {}).get("turns", 0) or 0),
                    role=str(r.get("metadata", {}).get("role", "")).replace("role_", ""),
                ))
            self.pairs[(data.get("strategy", jf.parent.parent.name),
                        data.get("layer", jf.parent.name))] = Pair(
                strategy=data.get("strategy", jf.parent.parent.name),
                layer=data.get("layer", jf.parent.name), cells=cells, done=True)

    # -- live tail -----------------------------------------------------------
    def refresh_live(self) -> None:
        text = _tail(SWEEP_LOG, 8000)
        layer = strat = ""
        for m in _LAYER_HDR.finditer(text):
            strat, layer = m.group(1), m.group(2)
        # Fallback: derive the live strategy/layer from the most-recently
        # written run.log if the top-level sweep log is unavailable or quiet.
        if (not layer or not strat) and self.ctx.run_dir:
            nl = self._newest_runlog()
            if nl:
                strat, layer = nl.parent.parent.name, nl.parent.name
        live = Live(layer=layer, strategy=strat)
        for m in _RUN.finditer(text):
            live.idx, live.total = int(m.group(1)), int(m.group(2))
            live.goal = m.group(3)
        vs = list(_VERDICT.finditer(text))
        if vs:
            live.verdict = vs[-1].group(1)
        live.turns = self._chat(strat, layer, live.goal)
        self.live = live

    def _newest_runlog(self) -> Optional[Path]:
        rd = self.ctx.run_dir
        if not rd:
            return None
        logs = list(rd.glob("*/*/run.log"))
        return max(logs, key=_mtime) if logs else None

    def _chat(self, strat: str, layer: str, goal: str) -> list[Turn]:
        rd = self.ctx.run_dir
        if not rd or not strat or not layer:
            return []
        return _chat_from_runlog(rd / strat / layer / "run.log")

    def matrix(self):
        m = self.ctx.manifest
        layers = m.layers or LAYER_ORDER
        strats = m.strategies or ["crescendo"]
        return strats, layers


def _mtime(p: Path) -> float:
    try:
        return p.stat().st_mtime
    except Exception:
        return 0.0


def _tail(p: Optional[Path], n: int) -> str:
    if not p or not p.exists():
        return ""
    try:
        with open(p, "rb") as fh:
            fh.seek(0, 2)
            sz = fh.tell()
            fh.seek(max(0, sz - n))
            return fh.read().decode("utf-8", "replace")
    except Exception:
        return ""


_LAYER_TOK = r"D0|DA|DB|DC-a|DC-b|DC-c|D\+\+|DT|\u2014"
_ROW = re.compile(
    r"^\s*(\d+)\s{2,}(.+?)\s{2,}(.+?)\s{2,}(" + _LAYER_TOK + r")\b\s*(\U0001f6a9)?\s*$"
)


def _chat_from_runlog(p: Path) -> list[Turn]:
    """Parse the last conversation panel into clean attacker/victim turns.

    Conversation rows are space-separated columns rendered inside a panel:
        ``│  3  <attacker prompt>   <victim response>   D0   ⚑ │``
    We scan from the last panel start (╭), strip the outer ``│`` border, and
    keep numbered rows; header/separator rows simply don't match the pattern.
    """
    text = _tail(p, 16000)
    panels = [b for b in text.split("\u256d") if "Attacker" in b]  # ╭
    rows = (panels[-1] if panels else "").splitlines()
    turns: list[Turn] = []
    for ln in rows:
        core = ln.strip().strip("\u2502").strip()  # drop outer │ border
        m = _ROW.match(core)
        if not m:
            continue
        turns.append(Turn(n=int(m.group(1)), prompt=m.group(2).strip(),
                          response=m.group(3).strip(), flag=bool(m.group(5))))
    return turns[-30:]
