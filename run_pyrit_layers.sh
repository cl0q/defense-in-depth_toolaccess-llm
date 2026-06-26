#!/usr/bin/env bash
# run_pyrit_layers.sh — PyRIT agentic red-team matrix runner
#
# Mirrors run_promptfoo_layers.sh: for every layer profile it applies the
# defense configuration, (optionally) restarts the gateway, then runs
# run_pyrit.py for each attack strategy so every layer×strategy pair gets
# its own artifact.
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
#   PYRIT_STRATEGIES=crescendo,tap bash run_pyrit_layers.sh
#   PYRIT_STRATEGY=redteam bash run_pyrit_layers.sh   # single-strategy compat
#   PYRIT_GOALS=G-R1,G-R2 bash run_pyrit_layers.sh
#
# Directory layout:  <artifact_root>/<run_id>/<strategy>/<layer>/
#   pyrit.results.json  — attack results (analysis/stats.py compatible)
#   run.log             — runner stdout/stderr
#   pyrit.db            — PyRIT SQLite memory (optional, --db-path)
#   gateway.log         — gateway stdout (one file per layer, shared across strategies)
#   power_log.jsonl     — per-call energy measurements
#
# Output is teed to per-run.log, so colours are auto-disabled there to keep
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
# PYRIT_STRATEGIES accepts a comma-separated list; PYRIT_STRATEGY (singular) is
# kept for backward compatibility when only one strategy is wanted.
strategies_csv="${PYRIT_STRATEGIES:-${PYRIT_STRATEGY:-crescendo}}"
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
strategies=$strategies_csv
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

# ---------------------------------------------------------------------------
# Preflight: warn/abort if something is already bound to the gateway port
# ---------------------------------------------------------------------------
preflight_check() {
  if [ "$gateway_manage" != "1" ]; then
    return 0   # user is managing the gateway themselves — not our problem
  fi
  local pid=""
  # ss is available on almost all modern Linux; fall back to lsof if not.
  # `|| true` is essential: when the port is FREE, grep/lsof exit non-zero and
  # would trip `set -o pipefail` + `set -e`, aborting the whole sweep.
  if command -v ss &>/dev/null; then
    pid=$( { ss -tlnp "sport = :${gateway_port}" 2>/dev/null \
             | grep -oP 'pid=\K[0-9]+' | head -1; } || true )
  elif command -v lsof &>/dev/null; then
    pid=$( { lsof -ti "tcp:${gateway_port}" 2>/dev/null | head -1; } || true )
  fi
  if [ -n "$pid" ]; then
    local cmd
    cmd=$(ps -p "$pid" -o comm= 2>/dev/null || echo "?")
    # Port 8000 is exclusively the gateway in this stack (victim=8001,
    # attacker=8002, guard=8003), so a listener here is almost always an
    # orphaned gateway from a previous/interrupted run. Auto-recover since we
    # manage the gateway ourselves (GATEWAY_MANAGE=1).
    echo "[preflight] port ${gateway_port} already in use by pid ${pid} (${cmd}); reclaiming it..."
    local all
    all=$( { ss -tlnp "sport = :${gateway_port}" 2>/dev/null | grep -oP 'pid=\K[0-9]+' | sort -u; } \
           || { lsof -ti "tcp:${gateway_port}" 2>/dev/null | sort -u; } || true )
    [ -z "$all" ] && all="$pid"
    for p in $all; do kill "$p" 2>/dev/null || true; done
    sleep 1
    for p in $all; do kill -9 "$p" 2>/dev/null || true; done
    sleep 1
    pid=$( { ss -tlnp "sport = :${gateway_port}" 2>/dev/null | grep -oP 'pid=\K[0-9]+' | head -1; } \
           || { lsof -ti "tcp:${gateway_port}" 2>/dev/null | head -1; } || true )
    if [ -n "$pid" ]; then
      echo "[preflight] could not free port ${gateway_port} (pid ${pid} still listening). Aborting." >&2
      exit 1
    fi
    echo "[preflight] port ${gateway_port} is now free."
  fi
}
preflight_check

# Return the PID(s) currently listening on the gateway port (one per line).
listeners_on_port() {
  if command -v ss &>/dev/null; then
    { ss -tlnp "sport = :${gateway_port}" 2>/dev/null \
        | grep -oP 'pid=\K[0-9]+' | sort -u; } || true
  elif command -v lsof &>/dev/null; then
    { lsof -ti "tcp:${gateway_port}" 2>/dev/null | sort -u; } || true
  fi
}

# Kill anything still bound to the gateway port. This is the safety net that
# prevents an orphaned gateway from a previous/interrupted run (or a botched
# restart) from silently serving the wrong defense profile for the whole sweep.
free_gateway_port() {
  local pids
  pids="$(listeners_on_port)"
  [ -z "$pids" ] && return 0
  echo "[gateway] freeing port ${gateway_port} (stale pids: $(echo $pids | tr '\n' ' '))"
  for p in $pids; do kill "$p" 2>/dev/null || true; done
  sleep 1
  pids="$(listeners_on_port)"
  if [ -n "$pids" ]; then
    for p in $pids; do kill -9 "$p" 2>/dev/null || true; done
    sleep 1
  fi
}

stop_gateway() {
  if [ -n "$gateway_pid" ] && kill -0 "$gateway_pid" 2>/dev/null; then
    kill "$gateway_pid" 2>/dev/null || true
    local waited=0
    while kill -0 "$gateway_pid" 2>/dev/null && [ "$waited" -lt 10 ]; do
      sleep 0.5
      waited=$((waited + 1))
    done
    kill -9 "$gateway_pid" 2>/dev/null || true
    wait "$gateway_pid" 2>/dev/null || true
  fi
  gateway_pid=""
  # Belt-and-suspenders: ensure the port is actually free before the next start.
  free_gateway_port
}

# Assert the live gateway reports the layer profile we intended. Catches the
# class of bug where a stale/orphaned gateway keeps serving an old profile:
# without this, every layer silently ran as D0.
#
# DC-a and DC-b are database-side defenses (column grants / RLS) that carry no
# gateway flag.  Their gateway legitimately reports D0, so the D0 check is
# skipped for them — the "wrong gateway" signature we watch for is a non-DC
# profile claiming to be D0.
verify_active_layer() {
  local expected="$1"
  local reported
  reported="$(curl -fsS "http://${gateway_host}:${gateway_port}/layers" 2>/dev/null \
                | grep -oP '"active_layers"\s*:\s*\[\K[^]]*' | tr -d ' "' )"
  echo "[gateway] reports active_layers=[${reported}] (intended profile=${expected})"

  # DC-a and DC-b defenses live entirely in Postgres; the gateway carries no
  # extra flags for them and correctly reports D0.  Nothing to verify here.
  if [ "$expected" = "DC-a" ] || [ "$expected" = "DC-b" ]; then
    return 0
  fi

  if [ "$expected" = "D0" ]; then
    if [ "$reported" != "D0" ]; then
      echo "FATAL: D0 profile but gateway reports [${reported}]." >&2
      return 1
    fi
  else
    # Any non-baseline profile must NOT report a bare D0 (the orphan signature),
    # and must not be empty.
    if [ -z "$reported" ] || [ "$reported" = "D0" ]; then
      echo "FATAL: profile=${expected} but gateway reports [${reported}] — stale/orphaned gateway?" >&2
      return 1
    fi
  fi
}

start_gateway() {
  local log_file="$1"
  local power_log_file="$2"
  local expected_layer="$3"
  # exec replaces the subshell with uvicorn so $! IS the uvicorn PID. Without
  # exec, $! is the subshell and `kill` would orphan uvicorn, leaving it bound
  # to the port and serving a stale profile for the rest of the sweep.
  ( cd "$repo_root" && exec env PYTHONPATH=. POWER_LOG_FILE="$power_log_file" \
      "$gateway_python" -m uvicorn gateway.app:app \
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

  # Confirm OUR uvicorn (or its child) owns the port — not a leftover orphan.
  local owner
  owner="$(listeners_on_port | head -1)"
  if [ -n "$owner" ] && [ "$owner" != "$gateway_pid" ]; then
    local parent
    parent="$(ps -o ppid= -p "$owner" 2>/dev/null | tr -d ' ' || true)"
    if [ "$parent" != "$gateway_pid" ]; then
      echo "FATAL: port ${gateway_port} served by pid ${owner}, not our gateway ${gateway_pid} (orphan?)." >&2
      return 1
    fi
  fi

  echo "[gateway] up (pid=$gateway_pid) for ${expected_layer}"
  verify_active_layer "$expected_layer"
}

trap stop_gateway EXIT

layers=("D0" "DA" "DB" "DC-a" "DC-b" "DC-c" "D++" "DT")
if [ -n "$layers_override" ]; then
  # `read` returns non-zero at EOF (here-strings have no trailing delimiter);
  # the array is still populated, so swallow the status under `set -e`.
  IFS=',' read -r -a layers <<< "$layers_override" || true
fi

IFS=',' read -r -a strategies <<< "$strategies_csv" || true

for layer in "${layers[@]}"; do
  # gateway.log and power_log are per-layer (shared across strategies for
  # the same layer run, since the gateway is only restarted once per layer).
  layer_base_dir="$run_dir/$layer"
  mkdir -p "$layer_base_dir"

  gateway_log="$layer_base_dir/gateway.log"
  power_log="$layer_base_dir/power_log.jsonl"

  echo "=== Layer ${layer}: applying defense profile ===" | tee "$layer_base_dir/apply.log"
  "$repo_root/set_layer.sh" "$layer" 2>&1 | tee -a "$layer_base_dir/apply.log"

  if [ "$gateway_manage" = "1" ]; then
    stop_gateway
    start_gateway "$gateway_log" "$power_log" "$layer"
  else
    echo "GATEWAY_MANAGE=0: restart the gateway so ${layer} flags load, then press Enter."
    read -r _
  fi

  for strategy in "${strategies[@]}"; do
    strat_layer_dir="$run_dir/$strategy/$layer"
    mkdir -p "$strat_layer_dir"

    results_file="$strat_layer_dir/pyrit.results.json"
    log_file="$strat_layer_dir/run.log"
    db_file="$strat_layer_dir/pyrit.db"

    echo "Running PyRIT ${strategy} for layer ${layer}" | tee "$log_file"

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
done

stop_gateway

# ---------------------------------------------------------------------------
# Frictionless analysis: write a ready-to-run analyze.sh AND print a copy-paste
# command that covers everything (all artifacts + all per-layer power logs).
# ---------------------------------------------------------------------------
idle_baseline="${IDLE_BASELINE_FILE:-$repo_root/idle_baseline.jsonl}"
analyze_script="$run_dir/analyze.sh"

cat > "$analyze_script" <<EOF
#!/usr/bin/env bash
# Auto-generated by run_pyrit_layers.sh for run_id=$run_id
# Analyzes every layer's PyRIT results + power logs from this run.
set -euo pipefail
cd "$repo_root"
python analysis/stats.py \\
  --artifacts '$run_dir/**/pyrit.results.json' \\
  --power-log '$run_dir/**/power_log.jsonl' \\
  --idle-baseline '$idle_baseline' \\
  --out '$run_dir/report.md' \\
  --json-out '$run_dir/report.json' \\
  --power-out '$run_dir/power_report.json'
echo
echo "Report written to: $run_dir/report.md"
EOF
chmod +x "$analyze_script"

echo ""
echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║                        SWEEP COMPLETE                                  ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo ""
echo "  RUN ID:     $run_id"
echo "  Artifacts:  $run_dir"
echo "  Layers:     ${layers[*]}"
echo "  Strategies: ${strategies[*]}"
echo ""
echo "  ────────────────────────────────────────────────────────────────────"
echo "  ANALYZE EVERYTHING — just run:"
echo ""
echo "      bash $analyze_script"
echo ""
echo "  ...or copy-paste this full command:"
echo ""
echo "      python analysis/stats.py \\"
echo "        --artifacts '$run_dir/**/pyrit.results.json' \\"
echo "        --power-log '$run_dir/**/power_log.jsonl' \\"
echo "        --idle-baseline '$idle_baseline' \\"
echo "        --out '$run_dir/report.md' \\"
echo "        --json-out '$run_dir/report.json' \\"
echo "        --power-out '$run_dir/power_report.json'"
echo "  ────────────────────────────────────────────────────────────────────"
echo ""

if [ "${PYRIT_NO_ANALYZE:-0}" != "1" ]; then
  echo "  Running analysis automatically (set PYRIT_NO_ANALYZE=1 to skip)..."
  echo ""
  bash "$analyze_script" && echo "  ✓ Report ready: $run_dir/report.md"
fi
