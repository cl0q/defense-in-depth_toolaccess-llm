#!/usr/bin/env bash
# rdm.sh — bootstrap a self-contained venv and launch Red Team Monitoring.
# Run from the repo root: ./rdm.sh   (or: bash rdm.sh)
set -euo pipefail
cd "$(dirname "$0")"

VENV="rdm/.venv"
PY="$VENV/bin/python"

if [ ! -x "$PY" ]; then
  echo "[rdm] creating venv $VENV ..."
  python3 -m venv "$VENV"
  "$PY" -m pip install -q --upgrade pip
  "$PY" -m pip install -q -r rdm/requirements.txt
fi

exec "$PY" -m rdm "$@"
