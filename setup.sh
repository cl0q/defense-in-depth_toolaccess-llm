#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$script_dir"

skip_db=false
skip_gateway=false

for arg in "$@"; do
	case "$arg" in
		--skip-db)
			skip_db=true
			;;
		--skip-gateway)
			skip_gateway=true
			;;
		*)
			echo "Unknown argument: $arg"
			exit 1
			;;
	esac
done

python_bin=""
for candidate in python3 python py; do
	if command -v "$candidate" >/dev/null 2>&1; then
		python_bin="$candidate"
		break
	fi
done

if [ -z "$python_bin" ]; then
	echo "No Python interpreter found on PATH"
	exit 1
fi

echo "Installing shared Python dependencies"
"$python_bin" -m pip install pyyaml numpy matplotlib garak

if ! command -v promptfoo >/dev/null 2>&1; then
	if command -v npm >/dev/null 2>&1; then
		echo "Installing promptfoo globally"
		npm install -g promptfoo
	else
		echo "promptfoo is not installed and npm is unavailable"
		exit 1
	fi
fi

echo "Creating runtime directories"
mkdir -p "$repo_root/analysis/artifacts/promptfoo"
mkdir -p "$repo_root/analysis/artifacts/garak"
mkdir -p "$repo_root/garak_results"
mkdir -p "$repo_root/runs/stack"

export PYTHONPATH="$repo_root${PYTHONPATH:+:$PYTHONPATH}"

if [ "$skip_gateway" = false ]; then
	echo "Setting up gateway virtual environment"
	"$repo_root/setup_gateway.sh"
fi

if [ "$skip_db" = false ]; then
	echo "Bootstrapping database"
	"$repo_root/bootstrap_db.sh"
fi

echo "Setup complete."