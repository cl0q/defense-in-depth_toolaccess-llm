#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$script_dir"

gateway_host="${GATEWAY_HOST:-127.0.0.1}"
gateway_port="${GATEWAY_PORT:-8000}"
vllm_host="${VLLM_HOST:-0.0.0.0}"
vllm_port="${VLLM_PORT:-8001}"
model_name="${TARGET_MODEL:-Qwen/Qwen3.6-27B-FP8}"
served_model_name="${VLLM_SERVED_MODEL_NAME:-qwen3-27b}"
api_key="${VLLM_API_KEY:-token-abc123}"

gateway_python="${GATEWAY_PYTHON:-$repo_root/gateway/venv/bin/python}"
if [ ! -x "$gateway_python" ]; then
  gateway_python="${PYTHON:-}"
fi

if [ -z "$gateway_python" ]; then
  for candidate in python3 python py; do
    if command -v "$candidate" >/dev/null 2>&1; then
      gateway_python="$candidate"
      break
    fi
  done
fi

if [ -z "$gateway_python" ]; then
  echo "No Python interpreter found for the gateway"
  exit 1
fi

vllm_bin="${VLLM_BIN:-vllm}"

log_dir="$repo_root/runs/stack/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$log_dir"

export PYTHONPATH="$repo_root${PYTHONPATH:+:$PYTHONPATH}"
export LLM_ENDPOINT="${LLM_ENDPOINT:-http://127.0.0.1:${vllm_port}/v1/completions}"

wait_for_url() {
  local url="$1"
  local label="$2"
  local attempt=0

  until curl -fsS "$url" >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 60 ]; then
      echo "Timed out waiting for ${label} at ${url}"
      exit 1
    fi
    sleep 1
  done
}

cleanup() {
  if [ -n "${gateway_pid:-}" ] && kill -0 "$gateway_pid" >/dev/null 2>&1; then
    kill "$gateway_pid" >/dev/null 2>&1 || true
  fi
  if [ -n "${vllm_pid:-}" ] && kill -0 "$vllm_pid" >/dev/null 2>&1; then
    kill "$vllm_pid" >/dev/null 2>&1 || true
  fi
}

trap cleanup EXIT INT TERM

echo "Starting vLLM on ${vllm_host}:${vllm_port}"
"$vllm_bin" serve "$model_name" \
  --host "$vllm_host" \
  --port "$vllm_port" \
  --served-model-name "$served_model_name" \
  --api-key "$api_key" \
  > "$log_dir/vllm.log" 2>&1 &
vllm_pid=$!

wait_for_url "http://127.0.0.1:${vllm_port}/v1/models" "vLLM"

echo "Starting gateway on ${gateway_host}:${gateway_port}"
"$gateway_python" -m uvicorn gateway.app:app \
  --host "$gateway_host" \
  --port "$gateway_port" \
  > "$log_dir/gateway.log" 2>&1 &
gateway_pid=$!

wait_for_url "http://127.0.0.1:${gateway_port}/openapi.json" "gateway"

echo "Stack is ready. Logs are in ${log_dir}"
echo "Gateway: http://${gateway_host}:${gateway_port}/query"
echo "vLLM: http://127.0.0.1:${vllm_port}/v1"

wait