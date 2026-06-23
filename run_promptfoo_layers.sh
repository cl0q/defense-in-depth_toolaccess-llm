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
layers=D0,DA,DB,DC-a,DC-b,DC-c,D++,DT
EOF

layers=("D0" "DA" "DB" "DC-a" "DC-b" "DC-c" "D++" "DT")

for layer in "${layers[@]}"; do
  layer_dir="$run_dir/$layer"
  mkdir -p "$layer_dir"

  generated_config="$layer_dir/redteam.generated.yaml"
  results_file="$layer_dir/redteam.results.json"
  log_file="$layer_dir/run.log"

  echo "Running promptfoo red-team generation for ${layer}"
  "$promptfoo_bin" redteam generate \
    -c "$promptfoo_config" \
    -o "$generated_config" \
    --no-cache \
    --force \
    --no-progress-bar \
    --strict \
    2>&1 | tee "$log_file"

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

echo "Promptfoo artifacts written to ${run_dir}"