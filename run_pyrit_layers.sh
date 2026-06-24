#!/usr/bin/env bash
# run_pyrit_layers.sh — PyRIT agentic red-team matrix runner
#
# Mirrors run_promptfoo_layers.sh: for every layer profile it applies the
# defense configuration, (optionally) restarts the gateway, then runs
# run_pyrit.py so each layer gets its own crescendo/red-team artifact.
#
# Prerequisites
# -------------
#   • redteam/pyrit_venv created and pyrit installed:
#       python3 -m venv redteam/pyrit_venv
#       source redteam/pyrit_venv/bin/activate && pip install pyrit
#   • Victim (port 8001) and Attacker (port 8002) vLLM servers running.
#   • Env vars for the attacker LLM set (or defaults used below).
#
# Usage
# -----
#   bash run_pyrit_layers.sh
#   GATEWAY_MANAGE=0 bash run_pyrit_layers.sh   # manage gateway yourself
#   PYRIT_STRATEGY=redteam bash run_pyrit_layers.sh
#   PYRIT_GOALS=G-R1,G-R2 bash run_pyrit_layers.sh
#
# Output is teed to per-layer run.log, so colours are auto-disabled there to keep
# logs clean.  Single interactive runs (redteam/run_pyrit.py directly) get full
# colour automatically; set PYRIT_FORCE_COLOR=1 to force ANSI even through a pipe.

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$script_dir"

# --- Paths and identifiers ---------------------------------------------------
pyrit_python="${PYRIT_PYTHON:-$repo_root/redteam/pyrit_venv/bin/python}"
artifact_root="${PYRIT_ARTIFACT_ROOT:-$repo_root/analysis/artifacts/pyrit}"
run_id="${PYRIT_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
git_sha="${GIT_SHA:-$(git -C "$repo_root" rev-parse --short HEAD 2>/dev/null || echo unknown)}"

# --- Attack config -----------------------------------------------------------
strategy="${PYRIT_STRATEGY:-crescendo}"
goals="${PYRIT_GOALS:-}"          # empty = all goals
max_turns="${PYRIT_MAX_TURNS:-10}"
trials="${PYRIT_TRIALS:-1}"       # repeat each goal N times -> leak-rate
layers_override="${PYRIT_LAYERS:-}"  # CSV to restrict the matrix, e.g. D0,DA

# --- Gateway config (matches run_promptfoo_layers.sh) -----------------------
gateway_manage="${GATEWAY_MANAGE:-1}"
gateway_host="${GATEWAY_HOST:-127.0.0.1}"
gateway_port="${GATEWAY_PORT:-8000}"
gateway_health_url="${GATEWAY_HEALTH_URL:-http://${gateway_host}:${gateway_port}/openapi.json}"
gateway_python="${GATEWAY_PYTHON:-}"
if [ -z "$gateway_python" ]; then
  if [ -x "$repo_root/gateway/venv/bin/python" ]; then
    gateway_python="$repo_root/gateway/venv/bin/python"
  else
    gateway_python="python3"
  fi
fi
gateway_pid=""

# --- Attacker LLM (read natively by OpenAIChatTarget via OPENAI_CHAT_* vars) -
export OPENAI_CHAT_ENDPOINT="${PYRIT_ATTACKER_ENDPOINT:-http://127.0.0.1:8002/v1}"
export OPENAI_CHAT_KEY="${PYRIT_ATTACKER_API_KEY:-token-abc123}"
export OPENAI_CHAT_MODEL="${PYRIT_ATTACKER_MODEL:-hermes-70b}"

export PYRIT_GATEWAY_ENDPOINT="http://${gateway_host}:${gateway_port}/query"

# ---------------------------------------------------------------------------

run_dir="$artifact_root/$run_id"
mkdir -p "$run_dir"

cat > "$run_dir/manifest.txt" <<EOF
run_id=$run_id
git_sha=$git_sha
strategy=$strategy
goals=${goals:-all}
max_turns=$max_turns
trials=$trials
attacker_endpoint=$OPENAI_CHAT_ENDPOINT
attacker_model=$OPENAI_CHAT_MODEL
gateway_manage=$gateway_manage
gateway_endpoint=$PYRIT_GATEWAY_ENDPOINT
layers=D0,DA,DB,DC-a,DC-b,DC-c,D++,DT
EOF

if [ -n "$layers_override" ]; then
  sed -i "s/^layers=.*/layers=$layers_override/" "$run_dir/manifest.txt"
fi

stop_gateway() {
  if [ -n "$gateway_pid" ] && kill -0 "$gateway_pid" 2>/dev/null; then
    kill "$gateway_pid" 2>/dev/null || true
    wait "$gateway_pid" 2>/dev/null || true
  fi
  gateway_pid=""
}

start_gateway() {
  local log_file="$1"
  ( cd "$repo_root" && PYTHONPATH=. "$gateway_python" -m uvicorn gateway.app:app \
      --host "$gateway_host" --port "$gateway_port" >>"$log_file" 2>&1 ) &
  gateway_pid=$!

  local tries=0
  until curl -fsS -o /dev/null "$gateway_health_url" 2>/dev/null; do
    tries=$((tries + 1))
    if ! kill -0 "$gateway_pid" 2>/dev/null; then
      echo "Gateway process exited during startup; see $log_file" >&2
      return 1
    fi
    if [ "$tries" -ge 60 ]; then
      echo "Gateway did not become healthy within 60s; see $log_file" >&2
      return 1
    fi
    sleep 1
  done
  echo "[gateway] up (pid=$gateway_pid) for $(basename "$(dirname "$log_file")")"
}

trap stop_gateway EXIT

layers=("D0" "DA" "DB" "DC-a" "DC-b" "DC-c" "D++" "DT")
if [ -n "$layers_override" ]; then
  IFS=',' read -r -a layers <<< "$layers_override"
fi

for layer in "${layers[@]}"; do
  layer_dir="$run_dir/$layer"
  mkdir -p "$layer_dir"

  results_file="$layer_dir/pyrit.results.json"
  log_file="$layer_dir/run.log"
  gateway_log="$layer_dir/gateway.log"
  db_file="$layer_dir/pyrit.db"

  echo "=== Layer ${layer}: applying defense profile ===" | tee "$log_file"
  "$repo_root/set_layer.sh" "$layer" 2>&1 | tee -a "$log_file"

  if [ "$gateway_manage" = "1" ]; then
    stop_gateway
    start_gateway "$gateway_log"
  else
    echo "GATEWAY_MANAGE=0: restart the gateway so ${layer} flags load, then press Enter."
    read -r _
  fi

  echo "Running PyRIT ${strategy} for layer ${layer}" | tee -a "$log_file"

  goals_arg=""
  if [ -n "$goals" ]; then
    goals_arg="--goals $goals"
  fi

  "$pyrit_python" "$repo_root/redteam/run_pyrit.py" \
    --layer "$layer" \
    --output "$results_file" \
    --strategy "$strategy" \
    --max-turns "$max_turns" \
    --trials "$trials" \
    --run-id "$run_id" \
    --db-path "$db_file" \
    ${goals_arg} \
    2>&1 | tee -a "$log_file"
done

stop_gateway
echo "PyRIT artifacts written to ${run_dir}"
echo "Run analysis with:"
echo "  python analysis/stats.py --glob '${run_dir}/**/pyrit.results.json'"
