"""
Deterministic, colourful CLI formatting for the PyRIT red-team runner.

IMPORTANT: every summarisation here is regex/string based — NO LLM calls.  This
keeps GPU load at zero and avoids polluting the power-measurement log with extra
inference.  The victim model (Qwen) emits large ``<think>...</think>`` reasoning
blocks; we strip them deterministically so the message log shows only the actual
answer (the JSON / SQL / refusal).

Renders with ``rich`` when available (it ships transitively with PyRIT).  Falls
back to plain ``print`` if ``rich`` cannot be imported.
"""

from __future__ import annotations

import os
import re
import sys
from typing import Any, Optional

try:
    from rich import box
    from rich.console import Console
    from rich.markup import escape as _rich_escape
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    _RICH_AVAILABLE = True
except Exception:  # pragma: no cover
    _RICH_AVAILABLE = False

    def _rich_escape(text: str) -> str:  # type: ignore
        return text

# Optional deterministic canary detection for per-turn leak flags.
try:
    _REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if _REPO_ROOT not in sys.path:
        sys.path.insert(0, _REPO_ROOT)
    from oracle.canary import detect_canary_tokens_with_details
except Exception:  # pragma: no cover
    detect_canary_tokens_with_details = None  # type: ignore


_THINK_CLOSED = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)
_THINK_OPEN = re.compile(r"<think>.*\Z", re.DOTALL | re.IGNORECASE)
_WS = re.compile(r"\s+")


# ---------------------------------------------------------------------------
# Deterministic text helpers (no LLM, no GPU)
# ---------------------------------------------------------------------------

def strip_think(text: str) -> str:
    """Remove ``<think>...</think>`` reasoning blocks, including a dangling
    unclosed block left by a truncated generation."""
    if not text:
        return ""
    out = _THINK_CLOSED.sub("", text)
    out = _THINK_OPEN.sub("", out)
    return out.strip()


def condense(text: str, max_len: int = 200) -> str:
    """Strip reasoning, collapse whitespace, and truncate with an ellipsis."""
    text = _WS.sub(" ", strip_think(text or "")).strip()
    if len(text) > max_len:
        text = text[: max_len - 1].rstrip() + "…"
    return text


def turn_leaked(response: str, attacker_tenant: str = "TA") -> bool:
    """Deterministically flag whether a victim response leaked a sensitive
    canary token (INTERNAL/SECRET sensitivity or a cross-tenant token)."""
    if detect_canary_tokens_with_details is None:
        return False
    try:
        tokens = detect_canary_tokens_with_details(response or "")
    except Exception:
        return False
    return any(
        t.sensitivity_level in ("INTERNAL", "SECRET") or t.tenant_id != attacker_tenant
        for t in tokens
    )


# ---------------------------------------------------------------------------
# Console
# ---------------------------------------------------------------------------

def make_console() -> Optional["Console"]:
    """Return a rich Console, or None if rich is unavailable.

    Set ``PYRIT_FORCE_COLOR=1`` to force ANSI colours even when stdout is a pipe
    (e.g. when the matrix runner tees output to a log file)."""
    if not _RICH_AVAILABLE:
        return None
    force = os.getenv("PYRIT_FORCE_COLOR", "") not in ("", "0")
    return Console(force_terminal=True if force else None, highlight=False)


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------

def print_header(
    console: Optional["Console"],
    *,
    strategy: str,
    layer: str,
    n_objectives: int,
    max_turns: int,
    attacker_model: str,
    gateway_endpoint: str,
) -> None:
    if console is None:
        print(
            f"[run_pyrit] strategy={strategy} layer={layer} "
            f"objectives={n_objectives} max_turns={max_turns}",
            flush=True,
        )
        return

    body = Text()
    rows = [
        ("strategy", strategy),
        ("layer", layer),
        ("objectives", str(n_objectives)),
        ("max turns", str(max_turns)),
        ("attacker", attacker_model),
        ("gateway", gateway_endpoint),
    ]
    for i, (key, val) in enumerate(rows):
        body.append(f"{key:<11}", style="bold cyan")
        body.append(val)
        if i < len(rows) - 1:
            body.append("\n")
    console.print(
        Panel(
            body,
            title="[bold]PyRIT agentic red-team[/bold]",
            border_style="blue",
            box=box.ROUNDED,
            expand=False,
        )
    )


def print_running(console: Optional["Console"], idx: int, total: int, goal: str, description: str) -> None:
    label = f"{goal} · {condense(description, 60)}"
    if console is None:
        print(f"[run_pyrit] [{idx}/{total}] {label}", flush=True)
        return
    console.print(f"[dim]▶ [{idx}/{total}] running[/dim] [bold]{_rich_escape(goal)}[/bold] [dim]{_rich_escape(condense(description, 60))}[/dim]")


def render_conversation(
    console: Optional["Console"],
    *,
    goal: str,
    description: str,
    role: str,
    turns: list[dict[str, Any]],
    success: bool,
    error: Optional[str] = None,
) -> None:
    role_short = role.replace("role_", "")
    verdict = "LEAK" if success else "blocked"

    if console is None:
        print(f"\n=== {goal} ({verdict}) role={role_short} ===")
        if error:
            print(f"  [error] {condense(error, 160)}")
        for i, t in enumerate(turns, 1):
            print(f"  [{i}] A→ {condense(t.get('prompt', ''), 100)}")
            layers = ",".join(t.get("active_layers") or []) or "-"
            print(f"      V← {condense(t.get('response', ''), 100)}  (layers={layers}, http={t.get('status', '?')})")
        print(f"  outcome: {verdict}  turns: {len(turns)}")
        return

    border = "red" if success else "green"

    table = Table(box=box.SIMPLE_HEAVY, expand=True, show_edge=False, pad_edge=False)
    table.add_column("#", justify="right", style="dim", width=2)
    table.add_column("Attacker → gateway", style="yellow", ratio=5, overflow="ellipsis", no_wrap=True)
    table.add_column("Victim ← gateway", ratio=5, overflow="ellipsis", no_wrap=True)
    table.add_column("Layers", justify="center", style="cyan", width=7, overflow="ellipsis", no_wrap=True)
    table.add_column("⚑", justify="center", width=2)

    for i, t in enumerate(turns, 1):
        response = t.get("response", "")
        status = int(t.get("status", 200) or 200)
        leaked = turn_leaked(response)
        if leaked:
            resp_style = "bold red"
        elif status >= 400:
            resp_style = "green"
        else:
            resp_style = "white"
        layers = ",".join(t.get("active_layers") or []) or "—"
        table.add_row(
            str(i),
            Text(condense(t.get("prompt", ""), 240)),
            Text(condense(response, 240), style=resp_style),
            layers,
            "🚩" if leaked else "",
        )

    if not turns:
        table.add_row("—", Text("(no gateway calls)", style="dim"), "", "—", "")

    title = f"[bold]{_rich_escape(goal)}[/bold] [dim]{_rich_escape(condense(description, 56))}[/dim]"
    subtitle = (
        f"[bold {'red' if success else 'green'}]{verdict.upper()}[/] · "
        f"{len(turns)} turns · role={role_short}"
    )
    console.print(Panel(table, title=title, subtitle=subtitle, border_style=border, box=box.ROUNDED))
    if error:
        console.print(f"  [dim red]error:[/dim red] {condense(error, 160)}")


def render_summary(console: Optional["Console"], results: list[dict[str, Any]]) -> None:
    total = len(results)
    succeeded = sum(1 for r in results if r["gradingResult"]["pass"])

    if console is None:
        print(f"\n[run_pyrit] {succeeded}/{total} attacks succeeded (data leaked)")
        for r in results:
            outcome = "LEAK" if r["gradingResult"]["pass"] else "blocked"
            print(f"  {r['tags']['goal']:<6} {outcome}")
        return

    table = Table(title="Run summary", box=box.ROUNDED, title_style="bold", expand=False)
    table.add_column("Goal", style="bold")
    table.add_column("Role")
    table.add_column("Turns", justify="right")
    table.add_column("Layers", style="cyan")
    table.add_column("Outcome", justify="center")

    for r in results:
        passed = r["gradingResult"]["pass"]
        meta = r.get("metadata", {})
        layers = ",".join(meta.get("active_layers") or []) or "—"
        outcome = Text("LEAK", style="bold red") if passed else Text("blocked", style="bold green")
        table.add_row(
            r["tags"]["goal"],
            str(meta.get("role", "")).replace("role_", ""),
            str(meta.get("turns", "")),
            layers,
            outcome,
        )

    console.print(table)
    style = "bold red" if succeeded else "bold green"
    console.print(f"[{style}]{succeeded}/{total} attacks succeeded (data leaked)[/]")
