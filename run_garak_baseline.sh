#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$script_dir"

config_file="${GARAK_CONFIG:-$repo_root/garak_config.yaml}"
artifact_dir="${GARAK_ARTIFACT_DIR:-$repo_root/garak_results}"
analysis_artifact_root="${GARAK_ANALYSIS_ARTIFACT_ROOT:-$repo_root/analysis/artifacts/garak}"
run_id="${GARAK_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"

mkdir -p "$artifact_dir"
mkdir -p "$analysis_artifact_root/$run_id"

cat > "$analysis_artifact_root/$run_id/manifest.txt" <<EOF
run_id=$run_id
config_file=$config_file
artifact_dir=$artifact_dir
openai_api_base_url=${OPENAI_API_BASE_URL:-http://127.0.0.1:8001/v1}
EOF

export OPENAI_API_BASE_URL="${OPENAI_API_BASE_URL:-http://127.0.0.1:8001/v1}"
export OPENAI_BASE_URL="${OPENAI_BASE_URL:-http://127.0.0.1:8001/v1}"
export OPENAI_API_KEY="${OPENAI_API_KEY:-token-abc123}"

echo "Running garak baseline with ${config_file}"
garak --config "$config_file"

cp -R "$artifact_dir" "$analysis_artifact_root/$run_id/raw"

echo "Garak baseline tests complete"