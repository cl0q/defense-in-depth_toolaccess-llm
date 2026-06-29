"""
RDM Textual app: panels for progress, attacker↔victim chat, resources, energy.

Event-driven, single ~1s timer; all reads are cheap/cached. Mouse-clickable
matrix + vim and arrow keybinds. Falls back to a clear message if Textual is
missing (run rdm.sh to install).
"""

from __future__ import annotations

import re
import time

from .discover import discover
from .metrics import energy, gpu, host
from .parsers import State

try:
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Horizontal, Vertical
    from textual.widgets import DataTable, Footer, Static
    _OK = True
except Exception:  # pragma: no cover
    _OK = False

_THINK = re.compile(r"<think>.*?</think>", re.DOTALL | re.I)
_OPEN = re.compile(r"<think>.*\Z", re.DOTALL | re.I)
_WS = re.compile(r"\s+")
DOT = "\u25cf"
FLAG = "\U0001f6a9"


def clean(t: str, n: int = 400) -> str:
    t = _OPEN.sub("", _THINK.sub("", t or ""))
    t = _WS.sub(" ", t).strip()
    return t[: n - 1] + "\u2026" if len(t) > n else t


def fmt_layer(strat: str, layer: str, st: State) -> Text:
    p = st.pairs.get((strat, layer))
    if not p:
        return Text("·", style="dim")
    leaks, n = p.leaks, len(p.cells)
    return Text(f"{leaks}/{n}", style="bold red" if leaks else "green")


if _OK:

    class RDM(App):
        CSS = """
        Screen { layout: vertical; }
        #status { height: 3; border: round cyan; padding: 0 1; }
        #mid { height: 1fr; }
        #matrix { width: 40; border: round blue; }
        #chat { border: round magenta; padding: 0 1; }
        #bottom { height: 11; }
        #res { width: 1fr; border: round green; padding: 0 1; }
        #nrg { width: 1fr; border: round yellow; padding: 0 1; }
        """
        BINDINGS = [
            Binding("q,escape", "quit", "Quit"),
            Binding("r", "refresh", "Refresh"),
            Binding("space", "toggle", "Pause"),
            Binding("f", "follow", "Follow live"),
            Binding("j,down", "row(1)", "Down"),
            Binding("k,up", "row(-1)", "Up"),
            Binding("g", "top", "Top"),
            Binding("G", "bottom", "Bottom"),
        ]

        def __init__(self):
            super().__init__()
            self.ctx = discover()
            self.st = State(self.ctx)
            self.t0 = time.time()
            self.paused = False
            self.follow = True
            self.sel = (0, 0)

        def compose(self) -> ComposeResult:
            yield Static(id="status")
            with Horizontal(id="mid"):
                yield DataTable(id="matrix")
                yield Static(id="chat")
            with Horizontal(id="bottom"):
                yield Static(id="res")
                yield Static(id="nrg")
            yield Footer()

        def on_mount(self):
            self.tbl = self.query_one("#matrix", DataTable)
            self.tbl.cursor_type = "row"
            strats, layers = self.st.matrix()
            self.tbl.add_column("layer")
            for s in strats:
                self.tbl.add_column(s[:6])
            for ly in layers:
                self.tbl.add_row(ly, *["·"] * len(strats), key=ly)
            self.refresh_all()
            self.set_interval(1.0, self.refresh_all)

        def refresh_all(self):
            if not self.paused:
                self.ctx = discover()
                self.st.ctx = self.ctx
                self.st.refresh_results()
                self.st.refresh_live()
            strats, layers = self.st.matrix()
            for ly in layers:
                try:
                    for ci, s in enumerate(strats, 1):
                        self.tbl.update_cell(ly, self.tbl.ordered_columns[ci].key,
                                             fmt_layer(s, ly, self.st))
                except Exception:
                    pass
            self.query_one("#status", Static).update(self._status())
            self.query_one("#chat", Static).update(self._chat(strats, layers))
            self.query_one("#res", Static).update(self._res())
            self.query_one("#nrg", Static).update(self._nrg())

        def _status(self):
            m, lv = self.ctx.manifest, self.st.live
            live = self.ctx.live
            t = Text()
            t.append(f"{DOT} ", style="bold green" if live else "bold red")
            t.append("RDM ", style="bold")
            t.append(f"{self.ctx.run_id}", style="cyan")
            t.append(f"  layer={lv.layer or '—'} strat={lv.strategy or '—'}", style="white")
            t.append(f"  goal={lv.goal or '—'} [{lv.idx}/{lv.total}]", style="yellow")
            if lv.verdict:
                t.append(f"  {lv.verdict}", style="bold red" if lv.verdict == "LEAK" else "bold green")
            el = int(time.time() - self.t0)
            t.append(f"  ⏱{el//60}m{el%60:02d}s", style="dim")
            if self.paused:
                t.append("  PAUSED", style="bold yellow")
            return t

        def _chat(self, strats, layers):
            r, c = self.sel
            strat = strats[c] if c < len(strats) else (strats[0] if strats else "")
            layer = layers[r] if r < len(layers) else (layers[0] if layers else "")
            if self.follow:
                strat, layer = self.st.live.strategy or strat, self.st.live.layer or layer
            turns = self.st._chat(strat, layer, self.st.live.goal)
            tbl = Table.grid(expand=True)
            tbl.add_column(ratio=1)
            for tn in turns[-12:]:
                if tn.prompt:
                    tbl.add_row(Panel(Text(clean(tn.prompt, 200), justify="right"),
                                title=f"attacker #{tn.n}", border_style="yellow", width=80,
                                style="on grey7"), style="on default")
                if tn.response:
                    style = "bold red" if tn.flag else "white"
                    tbl.add_row(Panel(Text(clean(tn.response, 200)), title=f"victim {FLAG if tn.flag else ''}",
                                border_style="red" if tn.flag else "green"))
            return Panel(tbl, title=f"chat {strat}/{layer} {'(live)' if self.follow else ''}",
                         border_style="magenta")

        def _res(self):
            h, g = host(), gpu()
            t = Text()
            t.append("CPU ", style="bold cyan"); t.append(f"{h.cpu:5.1f}%   ")
            t.append("RAM ", style="bold cyan"); t.append(f"{h.ram_used:.1f}/{h.ram_total:.0f}G\n")
            if g.ok:
                t.append("GPU ", style="bold green"); t.append(f"{g.util:3d}% {g.power_w:6.1f}W  ")
                t.append("VRAM ", style="bold green"); t.append(f"{g.vram_used:.1f}/{g.vram_total:.0f}G\n")
                t.append(g.name, style="dim")
            else:
                t.append("GPU n/a", style="dim")
            return Panel(t, title="resources", border_style="green")

        def _nrg(self):
            e = energy(self.ctx)
            t = Text()
            t.append(f"calls {e.calls}\n", style="cyan")
            t.append(f"net   {e.net_wh:.3f} Wh\n", style="bold yellow")
            t.append(f"gross {e.total_wh:.3f} Wh  idle {e.idle_w or 0:.0f}W\n", style="dim")
            for ly, wh in list(e.per_layer.items())[:4]:
                t.append(f"{ly:<6}{wh:.3f}Wh  ", style="white")
            return Panel(t, title="energy", border_style="yellow")

        def action_refresh(self): self.refresh_all()
        def action_toggle(self): self.paused = not self.paused
        def action_follow(self): self.follow = not self.follow; self.refresh_all()
        def action_row(self, d): self.tbl.move_cursor(row=max(0, self.tbl.cursor_row + d))
        def action_top(self): self.tbl.move_cursor(row=0)
        def action_bottom(self): self.tbl.move_cursor(row=self.tbl.row_count - 1)

        def on_data_table_row_highlighted(self, ev):
            self.sel = (ev.cursor_row, 0); self.follow = False; self.refresh_all()


def run():
    if not _OK:
        print("Textual not installed. Run ./rdm.sh to bootstrap the venv.")
        return 1
    RDM().run()
    return 0
