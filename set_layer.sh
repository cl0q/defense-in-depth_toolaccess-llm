#!/usr/bin/env bash
# =============================================================================
# set_layer.sh  —  single source of truth for the defense-layer experiment matrix
# -----------------------------------------------------------------------------
# Switches the whole stack to one layer profile by doing TWO things atomically:
#   1. gateway side  -> writes LAYER_* flags into the gateway .env file
#                       (DA / DB / DT are *enforced* by the gateway; DC-a/b/c are
#                        written too so the gateway can *report* the active set).
#   2. database side -> applies the matching db/*.sql (layer ON) or
#                       db/teardown/*_down.sql (layer OFF) for DC-a/b/c.
#
# The gateway reads .env only at startup, so gateway-side flag changes require a
# gateway restart. DB-side changes take effect on the next transaction.
# run_promptfoo_layers.sh orchestrates the restart automatically.
#
# Usage:
#   ./set_layer.sh <D0|DA|DB|DC-a|DC-b|DC-c|DT|D++>
#
# Options (env):
#   GATEWAY_ENV_FILE   path to gateway .env            (default: <repo>/.env)
#   SET_LAYER_NO_DB=1  skip the database posture changes (gateway flags only)
#   SET_LAYER_DRY_RUN=1 print what would happen, change nothing
#
# Profiles (each row = which layers are ON):
#   profile  DA DB DC-a DC-b DC-c DT
#   D0        .  .   .    .    .   .   (no defenses baseline)
#   DA        x  .   .    .    .   .
#   DB        .  x   .    .    .   .
#   DC-a      .  .   x    .    .   .
#   DC-b      .  .   .    x    .   .
#   DC-c      .  .   .    .    x   .
#   DT        .  .   .    .    .   x
#   D++       x  x   x    x    x   x   (full defense-in-depth)
# =============================================================================
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$script_dir"

profile="${1:-}"
if [ -z "$profile" ]; then
  echo "Usage: $0 <D0|DA|DB|DC-a|DC-b|DC-c|DT|D++>" >&2
  exit 1
fi

# --- resolve profile -> per-layer booleans -----------------------------------
DA=0; DB=0; DCA=0; DCB=0; DCC=0; DT=0; D0=0
case "$profile" in
  D0)    D0=1 ;;
  DA)    DA=1 ;;
  DB)    DB=1 ;;
  DC-a)  DCA=1 ;;
  DC-b)  DCB=1 ;;
  DC-c)  DCC=1 ;;
  DT)    DT=1 ;;
  D++)   DA=1; DB=1; DCA=1; DCB=1; DCC=1; DT=1 ;;
  *) echo "Unknown profile: '$profile' (expected D0|DA|DB|DC-a|DC-b|DC-c|DT|D++)" >&2; exit 1 ;;
esac

bool() { [ "$1" -eq 1 ] && echo true || echo false; }

active_list="$(
  { [ $D0  -eq 1 ] && echo D0;   } || true
  { [ $DA  -eq 1 ] && echo DA;   } || true
  { [ $DB  -eq 1 ] && echo DB;   } || true
  { [ $DCA -eq 1 ] && echo DC-a; } || true
  { [ $DCB -eq 1 ] && echo DC-b; } || true
  { [ $DCC -eq 1 ] && echo DC-c; } || true
  { [ $DT  -eq 1 ] && echo DT;   } || true
)"
active_csv="$(echo "$active_list" | paste -sd, - 2>/dev/null || echo "$active_list" | tr '\n' ',' | sed 's/,$//')"

echo "=== set_layer: profile=$profile  active=[$active_csv] ==="

# --- gateway side: rewrite LAYER_* lines in .env -----------------------------
env_file="${GATEWAY_ENV_FILE:-$repo_root/.env}"

write_env() {
  local tmp
  tmp="$(mktemp)"
  # keep every non-LAYER_ line already present, then append the fresh flags
  if [ -f "$env_file" ]; then
    grep -v -E '^[[:space:]]*LAYER_(D0|DA|DB|DC_A|DC_B|DC_C|DT)[[:space:]]*=' "$env_file" > "$tmp" || true
  fi
  {
    echo "# --- defense layer flags (managed by set_layer.sh, profile=$profile) ---"
    echo "LAYER_D0=$(bool $D0)"
    echo "LAYER_DA=$(bool $DA)"
    echo "LAYER_DB=$(bool $DB)"
    echo "LAYER_DC_A=$(bool $DCA)"
    echo "LAYER_DC_B=$(bool $DCB)"
    echo "LAYER_DC_C=$(bool $DCC)"
    echo "LAYER_DT=$(bool $DT)"
  } >> "$tmp"
  mv "$tmp" "$env_file"
  echo "[gateway] wrote layer flags to $env_file"
}

if [ "${SET_LAYER_DRY_RUN:-0}" = "1" ]; then
  echo "[dry-run] would write gateway flags DA=$(bool $DA) DB=$(bool $DB) DC_A=$(bool $DCA) DC_B=$(bool $DCB) DC_C=$(bool $DCC) DT=$(bool $DT) -> $env_file"
else
  write_env
fi

# --- database side: apply up/down SQL for DC-a/b/c ---------------------------
if [ "${SET_LAYER_NO_DB:-0}" = "1" ]; then
  echo "[db] SET_LAYER_NO_DB=1 -> skipping database posture changes"
else
  # Load credentials the same way bootstrap_db.sh does.
  if [ -f "$repo_root/creds.txt" ]; then
    # shellcheck source=/dev/null
    source "$repo_root/creds.txt"
  fi
  db_name="${DB_NAME:-marketplace}"
  db_host="${PGHOST:-${DB_HOST:-localhost}}"
  db_port="${PGPORT:-${DB_PORT:-5432}}"
  db_superuser="${PGSUPERUSER:-${DB_SUPERUSER:-postgres}}"
  db_superpassword="${PGSUPERPASSWORD:-${DB_SUPERPASSWORD:-${PGPASSWORD:-}}}"

  export PGHOST="$db_host"
  export PGPORT="$db_port"
  export PGUSER="$db_superuser"
  [ -n "$db_superpassword" ] && export PGPASSWORD="$db_superpassword"

  apply_sql() {
    local rel="$1"
    if [ "${SET_LAYER_DRY_RUN:-0}" = "1" ]; then
      echo "[dry-run] [db] would apply db/$rel"
      return 0
    fi
    psql -h "$db_host" -p "$db_port" -U "$db_superuser" -d "$db_name" \
         -v ON_ERROR_STOP=1 -f "$repo_root/db/$rel" >/dev/null
    echo "[db] applied db/$rel"
  }

  # DC-a (grants): up- and down-scripts are both idempotent GRANT/REVOKE sets.
  if [ $DCA -eq 1 ]; then apply_sql "02_grants.sql"; else apply_sql "teardown/02_grants_down.sql"; fi

  # DC-b (RLS): reset to a clean state, then enable if requested. The up-script
  # uses CREATE POLICY (not idempotent), so always tear down first.
  apply_sql "teardown/03_rls_down.sql"
  if [ $DCB -eq 1 ]; then apply_sql "03_rls.sql"; fi

  # DC-c (masking): drop masked views first, then re-create if requested.
  apply_sql "teardown/04_masking_down.sql"
  if [ $DCC -eq 1 ]; then apply_sql "04_masking.sql"; fi
fi

echo "=== set_layer: profile=$profile applied (restart gateway to load flag changes) ==="
