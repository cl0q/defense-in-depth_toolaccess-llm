#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$script_dir"

promptfoo_bin="${PROMPTFOO_BIN:-promptfoo}"
promptfoo_config="${PROMPTFOO_CONFIG:-$repo_root/redteam/promptfooconfig.yaml}"
artifact_root="${PROMPTFOO_ARTIFACT_ROOT:-$repo_root/analysis/artifacts/promptfoo}"
run_id="${PROMPTFOO_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
git_sha="${GIT_SHA:-$(git -C "$repo_root" rev-parse --short HEAD 2>/dev/null || echo unknown)}"
attacker_base_url="${PROMPTFOO_ATTACKER_BASE_URL:-http://127.0.0.1:8002/v1}"
attacker_api_key="${PROMPTFOO_ATTACKER_API_KEY:-token-abc123}"

# --- gateway lifecycle (so each layer profile is actually loaded) ------------
# The gateway reads layer flags from .env only at startup, so this runner
# restarts it for every layer profile. Set GATEWAY_MANAGE=0 to manage it
# yourself (e.g. when running the gateway in a separate tmux pane).
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

export PROMPTFOO_DISABLE_REDTEAM_REMOTE_GENERATION=true
export PROMPTFOO_DISABLE_SHARING=true
export OPENAI_API_BASE_URL="$attacker_base_url"
export OPENAI_BASE_URL="$attacker_base_url"
export OPENAI_API_KEY="$attacker_api_key"

run_dir="$artifact_root/$run_id"
mkdir -p "$run_dir"

cat > "$run_dir/manifest.txt" <<EOF
run_id=$run_id
git_sha=$git_sha
promptfoo_config=$promptfoo_config
attacker_base_url=$attacker_base_url
gateway_manage=$gateway_manage
gateway_endpoint=http://${gateway_host}:${gateway_port}/query
layers=D0,DA,DB,DC-a,DC-b,DC-c,D++,DT
EOF

# Return the PID(s) currently listening on the gateway port (one per line).
listeners_on_port() {
  if command -v ss &>/dev/null; then
    { ss -tlnp "sport = :${gateway_port}" 2>/dev/null \
        | grep -oP 'pid=\K[0-9]+' | sort -u; } || true
  elif command -v lsof &>/dev/null; then
    { lsof -ti "tcp:${gateway_port}" 2>/dev/null | sort -u; } || true
  fi
}

# Kill anything still bound to the gateway port, so an orphaned gateway from a
# previous/interrupted run can't silently serve the wrong defense profile.
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
  free_gateway_port
}

# Assert the live gateway reports the layer profile we intended — guards against
# a stale/orphaned gateway serving an old profile (every layer silently running
# as D0).
verify_active_layer() {
  local expected="$1"
  local reported
  reported="$(curl -fsS "http://${gateway_host}:${gateway_port}/layers" 2>/dev/null \
                | grep -oP '"active_layers"\s*:\s*\[\K[^]]*' | tr -d ' "' )"
  echo "[gateway] reports active_layers=[${reported}] (intended profile=${expected})"
  if [ "$expected" = "D0" ]; then
    if [ "$reported" != "D0" ]; then
      echo "FATAL: D0 profile but gateway reports [${reported}]." >&2
      return 1
    fi
  else
    if [ -z "$reported" ] || [ "$reported" = "D0" ]; then
      echo "FATAL: profile=${expected} but gateway reports [${reported}] — stale/orphaned gateway?" >&2
      return 1
    fi
  fi
}

start_gateway() {
  local log_file="$1"
  local expected_layer="$2"
  # exec so $! IS the uvicorn PID; without it `kill` orphans uvicorn, which keeps
  # holding the port and serving a stale profile for the rest of the sweep.
  ( cd "$repo_root" && exec env PYTHONPATH=. "$gateway_python" -m uvicorn gateway.app:app \
      --host "$gateway_host" --port "$gateway_port" >>"$log_file" 2>&1 ) &
  gateway_pid=$!

  # Wait for readiness.
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

for layer in "${layers[@]}"; do
  layer_dir="$run_dir/$layer"
  mkdir -p "$layer_dir"

  generated_config="$layer_dir/redteam.generated.yaml"
  results_file="$layer_dir/redteam.results.json"
  log_file="$layer_dir/run.log"
  gateway_log="$layer_dir/gateway.log"

  echo "=== Layer ${layer}: applying defense profile ==="
  "$repo_root/set_layer.sh" "$layer" 2>&1 | tee "$log_file"

  if [ "$gateway_manage" = "1" ]; then
    stop_gateway
    start_gateway "$gateway_log" "$layer"
  else
    echo "GATEWAY_MANAGE=0: restart the gateway manually so ${layer} flags load, then press Enter."
    read -r _
  fi

  echo "Running promptfoo red-team generation for ${layer}"
  "$promptfoo_bin" redteam generate \
    -c "$promptfoo_config" \
    -o "$generated_config" \
    --no-cache \
    --force \
    --no-progress-bar \
    --strict \
    2>&1 | tee -a "$log_file"

  echo "Running promptfoo red-team evaluation for ${layer}"
  "$promptfoo_bin" redteam eval \
    -c "$generated_config" \
    -o "$results_file" \
    --no-cache \
    --no-share \
    --no-progress-bar \
    -j 1 \
    --tag config="$layer" \
    --tag git.sha="$git_sha" \
    --tag run.id="$run_id" \
    2>&1 | tee -a "$log_file"
done

stop_gateway
echo "Promptfoo artifacts written to ${run_dir}"
