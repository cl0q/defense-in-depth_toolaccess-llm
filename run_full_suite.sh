#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

export GATEWAY_PYTHON="$PWD/gateway/venv/bin/python"
export PYRIT_PYTHON="$PWD/redteam/pyrit_venv/bin/python"
export PYRIT_STRATEGIES="crescendo,redteam,tap"
export PYRIT_MAX_TURNS="${PYRIT_MAX_TURNS:-10}"
export PYRIT_RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
# Surface actual exception tracebacks from the attacker LLM when nodes fail.
# This is a no-op for crescendo/redteam but essential for diagnosing TAP node errors.
export PYRIT_DEBUG=1

# --- TAP reliability knobs (preserve result accuracy) -----------------------
# TAP processes tree nodes in parallel (PyRIT default batch_size=10), firing a
# burst of concurrent generations at the 70B attacker. Under that load the
# attacker drops connections / times out, and the failed branches are silently
# pruned — shrinking the tree and under-reporting attack success. batch_size=1
# serialises node processing: the tree is identical (same accuracy) but the
# attacker is never overloaded, and it matches the concurrency=1 power method.
export PYRIT_TAP_BATCH_SIZE="${PYRIT_TAP_BATCH_SIZE:-1}"
# Explicit attacker timeout + completion budget so a slow/large generation under
# load is neither cut off early nor truncated to an empty/invalid response.
export PYRIT_ATTACKER_TIMEOUT="${PYRIT_ATTACKER_TIMEOUT:-180}"
export PYRIT_ATTACKER_MAX_TOKENS="${PYRIT_ATTACKER_MAX_TOKENS:-2048}"
# Verbose enough to capture the real cause of any attacker failure (httpx status
# lines + full tracebacks via _LoggingPromptNormalizer). Set WARNING to quieten.
export PYRIT_LOG_LEVEL="${PYRIT_LOG_LEVEL:-INFO}"
# Optional extra throttle (requests/minute). Unset by default — batch_size=1
# already serialises attacker calls. Set e.g. 60 if the backend is still busy.
# export PYRIT_ATTACKER_RPM=60

echo "=== sweep starting: run_id=$PYRIT_RUN_ID ==="
echo "=== logs: analysis/artifacts/pyrit/$PYRIT_RUN_ID ==="

nohup bash run_pyrit_layers.sh > sweep_full.log 2>&1 &
echo "[sweep] pid=$! — tailing sweep_full.log (Ctrl-C is safe, sweep keeps running)"
tail -f sweep_full.log
