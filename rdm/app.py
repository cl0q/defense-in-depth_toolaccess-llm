"""
RDM Textual app — Red Team Monitoring.

Layout
------
  status bar (1 row)
  mid  : [matrix 38c | turns list 1fr | detail 1fr]
  bottom: [resources | energy]
  footer

Navigation
----------
  j/k or ↑↓    move rows in focused panel
  h/l or ←/→   switch between matrix columns (strategies) when in matrix;
                h = focus matrix, l = focus detail from turns
  Tab           cycle focus: matrix → turns → matrix
  Enter         in turns → focus detail
  f             toggle follow-live (auto-tracks running strat/layer)
  t             toggle Solarized Dark ↔ Light
  space         pause/resume
  q / Escape    quit
"""

from __future__ import annotations

import json
import re
import time

from .discover import discover
from .metrics import energy, gpu, host
from .parsers import State, Turn

try:
    from rich.text import Text
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Horizontal, ScrollableContainer, Vertical
    from textual.theme import Theme
    from textual.widgets import DataTable, Footer, Static
    _OK = True
except Exception:  # pragma: no cover
    _OK = False

_THINK = re.compile(r"<think>.*?</think>", re.DOTALL | re.I)
_OPEN = re.compile(r"<think>.*\Z", re.DOTALL | re.I)
_WS = re.compile(r"\s+")
DOT = "\u25cf"
FLAG = "\U0001f6a9"

# Palette — readable in both Solarized Dark and Light
C_BLUE   = "#268bd2"
C_CYAN   = "#2aa198"
C_YELLOW = "#b58900"
C_GREEN  = "#859900"
C_RED    = "#dc322f"
C_ORANGE = "#cb4b16"

SOLAR_DARK = dict(
    primary=C_BLUE, secondary=C_CYAN, accent=C_YELLOW,
    foreground="#93a1a1", background="#002b36", surface="#073642",
    panel="#073642", success=C_GREEN, warning=C_YELLOW,
    error=C_RED, dark=True,
)
SOLAR_LIGHT = dict(
    primary=C_BLUE, secondary=C_CYAN, accent=C_ORANGE,
    foreground="#586e75", background="#fdf6e3", surface="#eee8d5",
    panel="#eee8d5", success=C_GREEN, warning=C_ORANGE,
    error=C_RED, dark=False,
)


def clean(t: str, n: int = 400) -> str:
    t = _OPEN.sub("", _THINK.sub("", t or ""))
    t = _WS.sub(" ", t).strip()
    return t[: n - 1] + "\u2026" if len(t) > n else t


def pretty_json(s: str) -> str:
    s = s.strip()
    if not (s.startswith("{") or s.startswith("[")):
        return s
    try:
        return json.dumps(json.loads(s), indent=2, ensure_ascii=False)
    except Exception:
        return s


def fmt_cell(strat: str, layer: str, st: State) -> Text:
    p = st.pairs.get((strat, layer))
    if not p:
        return Text("·", style="dim")
    leaks, n = p.leaks, len(p.cells)
    return Text(f"{leaks}/{n}", style=f"bold {C_RED}" if leaks else f"{C_GREEN}")


if _OK:

    class RDM(App):
        CSS = """
        Screen  { layout: vertical; }
        #status { height: 3; border: round $secondary; padding: 0 1; }
        #mid    { height: 1fr; }
        #matrix { width: 38; border: round $primary; }
        #turns  { width: 1fr; border: round $accent; }
        #detail { width: 1fr; border: round $secondary;
                  overflow-y: auto; padding: 0 1; }
        #bottom { height: 12; }
        #res    { width: 1fr; border: round $success; padding: 0 1; }
        #nrg    { width: 1fr; border: round $warning; padding: 0 1; }
        """
        BINDINGS = [
            Binding("q,escape",  "quit",        "Quit"),
            Binding("r",         "refresh",     "Refresh"),
            Binding("space",     "toggle",      "Pause"),
            Binding("f",         "follow",      "Follow"),
            Binding("t",         "next_theme",  "Theme"),
            Binding("j,down",    "nav_down",    "Down"),
            Binding("k,up",      "nav_up",      "Up"),
            Binding("g",         "top",         "Top"),
            Binding("G",         "bottom",      "Bottom"),
            Binding("l,right",   "focus_right", "→ turns"),
            Binding("h,left",    "focus_left",  "← matrix"),
            Binding("enter",     "select",      "Select"),
            Binding("tab",       "focus_next",  "Next", show=False),
        ]

        def __init__(self):
            super().__init__()
            self.ctx    = discover()
            self.st     = State(self.ctx)
            self.paused = False
            self.follow = True
            # (layer_idx, strat_idx) — both 0-based into manifest lists
            self.sel    = (0, 0)
            self._cur_turns: list[Turn] = []
            self._turns_key = ("", "")   # (strat, layer) last loaded
            self._sel_turn: int = 0      # index into _cur_turns

        # ── layout ────────────────────────────────────────────────────────

        def compose(self) -> ComposeResult:
            yield Static(id="status")
            with Horizontal(id="mid"):
                yield DataTable(id="matrix")
                yield DataTable(id="turns")
                with ScrollableContainer(id="detail"):
                    yield Static(id="detail-text")
            with Horizontal(id="bottom"):
                yield Static(id="res")
                yield Static(id="nrg")
            yield Footer()

        def on_mount(self):
            for name, cfg in (("solarized-dark", SOLAR_DARK),
                               ("solarized-light", SOLAR_LIGHT)):
                try:
                    self.register_theme(Theme(name=name, **cfg))
                except Exception:
                    pass
            self.theme = "solarized-dark"

            # matrix — cursor on cell so h/l selects strategy column
            self.tbl = self.query_one("#matrix", DataTable)
            self.tbl.cursor_type = "cell"
            strats, layers = self.st.matrix()
            self.tbl.add_column("layer", width=8)
            for s in strats:
                self.tbl.add_column(s[:8], width=8)
            for ly in layers:
                self.tbl.add_row(ly, *["·"] * len(strats), key=ly)

            # turns DataTable
            self.turns_tbl = self.query_one("#turns", DataTable)
            self.turns_tbl.cursor_type = "row"
            self.turns_tbl.add_column("#",  width=3)
            self.turns_tbl.add_column("attacker", width=40)
            self.turns_tbl.add_column("victim",   width=50)
            self.turns_tbl.add_column("⚑",        width=2)
            self.turns_tbl.show_header = True

            self.refresh_all()
            self.set_interval(1.0, self.refresh_all)

        # ── refresh ───────────────────────────────────────────────────────

        def refresh_all(self):
            if not self.paused:
                self.ctx    = discover()
                self.st.ctx = self.ctx
                self.st.refresh_results()
                self.st.refresh_live()
            strats, layers = self.st.matrix()
            self._rebuild_matrix(strats, layers)
            self.query_one("#status", Static).update(self._status())
            self._sync_turns(strats, layers)
            self.query_one("#res", Static).update(self._res())
            self.query_one("#nrg", Static).update(self._nrg())

        def _rebuild_matrix(self, strats, layers):
            for li, ly in enumerate(layers):
                for ci, s in enumerate(strats):
                    try:
                        col_key = self.tbl.ordered_columns[ci + 1].key
                        self.tbl.update_cell(ly, col_key, fmt_cell(s, ly, self.st))
                    except Exception:
                        pass

        def _resolve_sel(self, strats, layers):
            """Return (strat, layer) from current selection or live state."""
            li, ci = self.sel
            strat = strats[ci] if ci < len(strats) else (strats[0] if strats else "")
            layer = layers[li] if li < len(layers) else (layers[0] if layers else "")
            if self.follow:
                strat = self.st.live.strategy or strat
                layer = self.st.live.layer or layer
            return strat, layer

        def _sync_turns(self, strats, layers):
            strat, layer = self._resolve_sel(strats, layers)
            key = (strat, layer)
            turns = self.st.live.turns if self.follow else self.st._chat(strat, layer, "")
            if key != self._turns_key or len(turns) != len(self._cur_turns):
                self._turns_key  = key
                self._cur_turns  = turns
                self._load_turns_table(turns, strat, layer)
            # update detail for current selection
            if self._cur_turns and 0 <= self._sel_turn < len(self._cur_turns):
                self._show_detail(self._cur_turns[self._sel_turn])

        def _load_turns_table(self, turns: list[Turn], strat: str, layer: str):
            dt = self.turns_tbl
            dt.clear()
            for tn in turns:
                a = Text(clean(tn.prompt,   45), style=C_YELLOW)
                v = Text(clean(tn.response, 55), style=f"bold {C_RED}" if tn.flag else "")
                dt.add_row(str(tn.n), a, v, FLAG if tn.flag else "", key=str(tn.n))
            # scroll to bottom (latest turn) when following live
            if turns and self.follow:
                dt.move_cursor(row=len(turns) - 1)
                self._sel_turn = len(turns) - 1
            title = f"chat  {strat}/{layer}{'  (live)' if self.follow else ''}"
            try:
                self.query_one("#turns").border_title = title
            except Exception:
                pass

        def _show_detail(self, tn: Turn):
            t = Text()
            if tn.prompt:
                t.append("ATTACKER\n", style=f"bold {C_YELLOW}")
                t.append(clean(tn.prompt, 4000) + "\n\n", style=C_YELLOW)
            if tn.response:
                lbl = f"VICTIM  {FLAG}\n" if tn.flag else "VICTIM\n"
                t.append(lbl, style=f"bold {C_RED}" if tn.flag else f"bold {C_CYAN}")
                t.append(pretty_json(clean(tn.response, 8000)),
                         style=f"bold {C_RED}" if tn.flag else "")
            self.query_one("#detail-text", Static).update(t)

        # ── status ────────────────────────────────────────────────────────

        def _status(self):
            lv   = self.st.live
            live = self.ctx.live
            t    = Text()
            t.append(f"{DOT} ", style=f"bold {C_GREEN}" if live else f"bold {C_RED}")
            t.append("RDM ", style="bold")
            t.append(f"{self.ctx.run_id}", style=C_BLUE)
            t.append(f"  layer=", style="bold"); t.append(lv.layer or "—")
            t.append(f"  strat=", style="bold"); t.append(lv.strategy or "—")
            t.append(f"  goal=", style="bold");  t.append(lv.goal or "—")
            t.append(f" [{lv.idx}/{lv.total}]", style=C_YELLOW)
            if lv.verdict:
                t.append(f"  {lv.verdict}",
                         style=f"bold {C_RED}" if lv.verdict == "LEAK" else f"bold {C_GREEN}")
            start = self.ctx.start_epoch
            el = int(time.time() - start) if start else 0
            t.append(f"  \u23f1 {el//60}m{el%60:02d}s", style="dim")
            if self.paused:
                t.append("  PAUSED", style=f"bold {C_ORANGE}")
            return t

        # ── resource / energy panels ──────────────────────────────────────

        def _res(self):
            h, g = host(), gpu()
            t = Text()
            t.append("CPU ", style=f"bold {C_CYAN}")
            t.append(f"{h.cpu:5.1f}%   ")
            t.append("RAM ", style=f"bold {C_CYAN}")
            t.append(f"{h.ram_used:.1f}/{h.ram_total:.0f} GiB\n")
            if g.ok:
                t.append("GPU ", style=f"bold {C_GREEN}")
                t.append(f"{g.util:3d}%  ")
                t.append(f"{g.power_w:6.1f} W  ")
                t.append("VRAM ", style=f"bold {C_GREEN}")
                t.append(f"{g.vram_used:.1f}/{g.vram_total:.0f} GiB\n")
                t.append(g.name, style="dim")
            else:
                t.append("GPU n/a", style="dim")
            return t

        def _nrg(self):
            e = energy(self.ctx)
            t = Text()
            t.append(f"calls  {e.calls}\n", style=C_CYAN)
            t.append(f"net    {e.net_wh:.4f} Wh\n", style=f"bold {C_YELLOW}")
            t.append(f"gross  {e.total_wh:.4f} Wh", style="dim")
            t.append(f"  idle {e.idle_w or 0:.0f} W\n", style="dim")
            for ly, wh in list(e.per_layer.items())[:5]:
                t.append(f"  {ly:<6}", style=f"bold {C_BLUE}")
                t.append(f"{wh:.4f} Wh\n")
            return t

        # ── actions ────────────────────────────────────────────────────────

        def action_refresh(self):
            self.refresh_all()

        def action_toggle(self):
            self.paused = not self.paused

        def action_follow(self):
            self.follow = not self.follow
            self._turns_key = ("", "")  # force reload
            self.refresh_all()

        def action_next_theme(self):
            self.theme = ("solarized-light"
                          if self.theme == "solarized-dark"
                          else "solarized-dark")

        def action_nav_down(self):
            fw = self.focused
            if fw is self.tbl:
                self.tbl.action_scroll_down()
            elif fw is self.turns_tbl:
                self.turns_tbl.action_scroll_down()

        def action_nav_up(self):
            fw = self.focused
            if fw is self.tbl:
                self.tbl.action_scroll_up()
            elif fw is self.turns_tbl:
                self.turns_tbl.action_scroll_up()

        def action_top(self):
            fw = self.focused
            if fw is self.tbl:
                self.tbl.move_cursor(row=0)
            elif fw is self.turns_tbl:
                self.turns_tbl.move_cursor(row=0)

        def action_bottom(self):
            fw = self.focused
            if fw is self.tbl:
                self.tbl.move_cursor(row=self.tbl.row_count - 1)
            elif fw is self.turns_tbl:
                r = self.turns_tbl.row_count - 1
                self.turns_tbl.move_cursor(row=max(0, r))

        def action_focus_right(self):
            fw = self.focused
            if fw is self.tbl:
                # l in matrix: move strategy column right
                nc = min(len(self.st.matrix()[0]), self.tbl.cursor_column + 1)
                self.tbl.move_cursor(column=nc)
                self.follow = False; self._turns_key = ("", ""); self.refresh_all()
            else:
                self.turns_tbl.focus()

        def action_focus_left(self):
            fw = self.focused
            if fw is self.turns_tbl:
                self.tbl.focus()
            elif fw is self.query_one("#detail"):
                self.turns_tbl.focus()
            else:
                # in matrix: move strategy column left (stop at col 1)
                nc = max(1, self.tbl.cursor_column - 1)
                self.tbl.move_cursor(column=nc)
                self.follow = False
                self._turns_key = ("", "")
                self.refresh_all()

        def action_select(self):
            if self.focused is self.turns_tbl:
                self.query_one("#detail").focus()

        def action_focus_next(self):
            if self.focused is self.tbl:
                self.turns_tbl.focus()
            else:
                self.tbl.focus()

        # ── events ────────────────────────────────────────────────────────

        def on_data_table_cell_highlighted(self, ev: DataTable.CellHighlighted):
            if ev.data_table is not self.tbl:
                return
            # column 0 is the "layer" label; strategy idx = cursor_column - 1
            strat_idx = max(0, self.tbl.cursor_column - 1)
            self.sel = (self.tbl.cursor_row, strat_idx)
            self.follow = False
            self._turns_key = ("", "")
            self.refresh_all()

        def on_data_table_row_highlighted(self, ev: DataTable.RowHighlighted):
            if ev.data_table is not self.turns_tbl:
                return
            self._sel_turn = ev.cursor_row
            if 0 <= ev.cursor_row < len(self._cur_turns):
                self._show_detail(self._cur_turns[ev.cursor_row])


def run():
    if not _OK:
        print("Textual not installed. Run ./rdm.sh to bootstrap the venv.")
        return 1
    RDM().run()
    return 0

