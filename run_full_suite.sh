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

# --- Victim-side (gateway) timeout ------------------------------------------
# The victim is a reasoning model behind heavy defense layers (D++/DT); its
# replies can exceed the old hard-coded 120 s, surfacing as crescendo
# ReadTimeouts that abort otherwise-valid objectives. Raise the gateway HTTP
# timeout so slow-but-legitimate victim turns complete instead of being lost.
export PYRIT_GATEWAY_TIMEOUT="${PYRIT_GATEWAY_TIMEOUT:-300}"

# --- Output / colour QoL -----------------------------------------------------
# Force rich (Python) colour + a wide console THROUGH the tee pipe, so the
# conversation tables in sweep_full.log render in colour and fit far more
# content when `tail -f`'d. PYRIT_MSG_MAXLEN controls how much of each
# attacker/victim message is shown per turn (wrapped, not ellipsised).
export PYRIT_FORCE_COLOR="${PYRIT_FORCE_COLOR:-1}"
export PYRIT_CONSOLE_WIDTH="${PYRIT_CONSOLE_WIDTH:-140}"
export PYRIT_MSG_MAXLEN="${PYRIT_MSG_MAXLEN:-600}"
# Force colour for the bash scaffolding (lib/log.sh) inside the backgrounded,
# piped layers script too. Set SWEEP_COLOR=0 (and PYRIT_FORCE_COLOR=0) if you
# prefer plain logs — e.g. to colourise them yourself with grc (see below).
export SWEEP_COLOR="${SWEEP_COLOR:-1}"

# Shared colourful / structured logging for this launcher.
# shellcheck source=lib/log.sh
source "$PWD/lib/log.sh"

log_step "starting sweep ${C_BOLD}${PYRIT_RUN_ID}${C_RESET}"

nohup bash run_pyrit_layers.sh > sweep_full.log 2>&1 &
SWEEP_PID=$!
echo "$SWEEP_PID" > "$PWD/.sweep.pid"

log_banner "Sweep launched · run ${PYRIT_RUN_ID}"
log_kv "sweep pid"  "${SWEEP_PID}"
log_kv "console"    "tail -f sweep_full.log"
log_kv "artifacts"  "analysis/artifacts/pyrit/${PYRIT_RUN_ID}"
log_kv "pid file"   "$PWD/.sweep.pid"
log_kv "stop with"  "kill ${SWEEP_PID}   ${C_DIM}(or: kill \$(cat .sweep.pid))${C_RESET}"
echo ""
log_info "tailing sweep_full.log — ${C_DIM}Ctrl-C is safe, the sweep keeps running in the background (pid ${SWEEP_PID})${C_RESET}"
log_rule
echo ""

# Live console. The stream already carries ANSI colour (rich + lib/log.sh), so
# the default tail is fully colourful with no extra tooling. Opt-in grc routing
# (SWEEP_TAIL_GRC=1) is provided for users who run with colour OFF and prefer
# grc's own scheme: `SWEEP_COLOR=0 PYRIT_FORCE_COLOR=0 SWEEP_TAIL_GRC=1 bash run_full_suite.sh`.
if [ "${SWEEP_TAIL_GRC:-0}" = "1" ] && command -v grcat >/dev/null 2>&1; then
  log_info "colourising tail via grc ${C_DIM}(SWEEP_TAIL_GRC=1 → lib/sweep.grcat)${C_RESET}"
  tail -n +1 -f sweep_full.log | grcat "$PWD/lib/sweep.grcat"
else
  tail -n +1 -f sweep_full.log
fi
