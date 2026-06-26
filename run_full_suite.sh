#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

export GATEWAY_PYTHON="$PWD/gateway/venv/bin/python"
export PYRIT_PYTHON="$PWD/redteam/pyrit_venv/bin/python"
export PYRIT_STRATEGIES="crescendo,redteam,tap"
export PYRIT_MAX_TURNS="${PYRIT_MAX_TURNS:-10}"
export PYRIT_RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"

echo "=== sweep starting: run_id=$PYRIT_RUN_ID ==="
echo "=== logs: analysis/artifacts/pyrit/$PYRIT_RUN_ID ==="

nohup bash run_pyrit_layers.sh > sweep_full.log 2>&1 &
echo "[sweep] pid=$! — tailing sweep_full.log (Ctrl-C is safe, sweep keeps running)"
tail -f sweep_full.log
