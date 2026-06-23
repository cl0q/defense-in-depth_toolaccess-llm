#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$script_dir"
venv_dir="$repo_root/gateway/venv"

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

echo "Setting up gateway dependencies"
"$python_bin" -m venv "$venv_dir"

if [ -f "$venv_dir/bin/activate" ]; then
	# shellcheck disable=SC1090
	source "$venv_dir/bin/activate"
else
	echo "Unable to find virtual environment activation script at $venv_dir/bin/activate"
	exit 1
fi

python -m pip install -r "$repo_root/gateway/requirements.txt"

echo "Gateway setup complete"
echo "Activate it with: source gateway/venv/bin/activate"