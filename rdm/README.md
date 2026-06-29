# RDM — Red Team Monitoring

Lightweight terminal dashboard that attaches to a **running** sweep
(`run_full_suite.sh`) and renders it nicely, instead of `tail -f sweep_full.log`.
Read-only: it just parses the logs/artifacts the sweep already writes.

## Run
```bash
./rdm.sh            # bootstraps rdm/.venv on first run, then launches
python3 rdm.py      # if deps already installed
./rdm.sh --selftest # parse bundled sample, no TUI
```

## Panels
- **Status** — run-id, live layer/strategy/goal, verdict, elapsed, live dot
- **Matrix** — leaks per layer×strategy (click or j/k to inspect)
- **Chat** — attacker (right) ↔ victim (left), 🚩 on canary leaks
- **Resources** — CPU/RAM, GPU util/W, VRAM (psutil + pynvml)
- **Energy** — per-attack Wh, net of `idle_baseline.jsonl`

## Keys
`q` quit · `r` refresh · `space` pause · `f` follow-live · `j/k`+arrows · `g/G` top/bottom · mouse.

Self-contained in `rdm/.venv`; nothing global. Lives alongside the sweep on the
Ubuntu host (tmux over SSH).
