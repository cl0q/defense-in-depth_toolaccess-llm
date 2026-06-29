"""Entry point: `python3 -m rdm` / `rdm.py`. Supports --selftest (no TUI)."""

from __future__ import annotations

import sys
from pathlib import Path


def selftest() -> int:
    from .discover import RunContext, Manifest
    from .parsers import State, _chat_from_runlog
    samples = Path(__file__).resolve().parent / "samples"
    run = _chat_from_runlog(samples / "run.log")
    print(f"[selftest] parsed {len(run)} chat turns from sample run.log")
    ctx = RunContext(run_dir=None, manifest=Manifest(run_id="SELFTEST",
                     strategies=["crescendo"], layers=["D0"]))
    st = State(ctx)
    st.matrix()
    ok = len(run) >= 3 and any(t.flag for t in run)
    print("[selftest] OK" if ok else "[selftest] FAILED")
    return 0 if ok else 1


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    from .app import run
    return run()


if __name__ == "__main__":
    raise SystemExit(main())
