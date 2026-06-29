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
import sqlite3
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
        if not text:
            return
        layer = strat = ""
        for m in _LAYER_HDR.finditer(text):
            strat, layer = m.group(1), m.group(2)
        live = Live(layer=layer, strategy=strat)
        for m in _RUN.finditer(text):
            live.idx, live.total = int(m.group(1)), int(m.group(2))
            live.goal = m.group(3)
        vs = list(_VERDICT.finditer(text))
        if vs:
            live.verdict = vs[-1].group(1)
        live.turns = self._chat(strat, layer, live.goal)
        self.live = live

    def _chat(self, strat: str, layer: str, goal: str) -> list[Turn]:
        rd = self.ctx.run_dir
        if not rd or not strat or not layer:
            return []
        db = rd / strat / layer / "pyrit.db"
        turns = _chat_from_db(db, goal) if db.exists() else []
        if not turns:
            turns = _chat_from_runlog(rd / strat / layer / "run.log")
        return turns

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


def _chat_from_db(db: Path, goal: str, limit: int = 30) -> list[Turn]:
    """Full transcript from PyRIT SQLite memory (read-only). Best-effort."""
    try:
        uri = f"file:{db}?mode=ro&immutable=1"
        con = sqlite3.connect(uri, uri=True, timeout=0.5)
        con.row_factory = sqlite3.Row
        rows = con.execute(
            "SELECT role, original_value, sequence FROM PromptMemoryEntries "
            "ORDER BY sequence DESC LIMIT ?", (limit * 2,)).fetchall()
        con.close()
    except Exception:
        return []
    pairs: dict[int, Turn] = {}
    for r in reversed(rows):
        seq, role, val = r["sequence"], (r["role"] or ""), (r["original_value"] or "")
        t = pairs.setdefault(seq, Turn(n=seq, prompt="", response=""))
        if role == "user":
            t.prompt = val
        elif role == "assistant":
            t.response = val
    return [pairs[k] for k in sorted(pairs)][-limit:]


def _chat_from_runlog(p: Path) -> list[Turn]:
    """Fallback: scrape the last conversation table (truncated cols)."""
    text = _tail(p, 12000)
    block = text.rsplit("\u256d", 1)  # last panel start ╭
    rows = (block[-1] if len(block) > 1 else text).splitlines()
    turns: list[Turn] = []
    for ln in rows:
        cells = [c.strip() for c in ln.split("\u2502")]  # │
        if len(cells) < 4 or not cells[1].isdigit():
            continue
        turns.append(Turn(n=int(cells[1]), prompt=cells[2], response=cells[3],
                          flag="\U0001f6a9" in ln))
    return turns[-30:]
