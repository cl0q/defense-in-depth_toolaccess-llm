#!/usr/bin/env bash
# lib/log.sh — shared, colourful, structured logging helpers for the sweep scripts.
#
# Source it after computing $repo_root:
#     source "$repo_root/lib/log.sh"
#
# Colour is enabled when stdout is a TTY, or forced via SWEEP_COLOR=1 /
# PYRIT_FORCE_COLOR=1 (used when the orchestrator tees output into a log that is
# later `tail -f`'d).  Respects the NO_COLOR convention and SWEEP_COLOR=0.
#
# Helpers:
#   log_info / log_warn / log_error / log_ok / log_step "<msg>"
#   log_kv "<key>" "<value>"            aligned key/value line
#   log_banner "<title>"               boxed section header
#   log_rule  ["<title>"]              horizontal rule (optional inline title)
#   fmt_elapsed <seconds>              -> "1h02m03s" / "2m05s" / "9s"
#   log_since "<msg>" <start_epoch>    log_ok with " (took …)" appended
#
# All helpers are safe under `set -euo pipefail`.

# --- colour detection --------------------------------------------------------
__sweep_color_enabled() {
  case "${NO_COLOR:-}" in ?*) return 1 ;; esac
  case "${SWEEP_COLOR:-}" in
    0|false|no|off) return 1 ;;
    1|true|yes|on)  return 0 ;;
  esac
  case "${PYRIT_FORCE_COLOR:-}" in
    1|true|yes|on)  return 0 ;;
  esac
  [ -t 1 ]
}

if __sweep_color_enabled; then
  C_RESET=$'\033[0m';  C_BOLD=$'\033[1m';   C_DIM=$'\033[2m'
  C_RED=$'\033[31m';   C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
  C_BLUE=$'\033[34m';  C_MAGENTA=$'\033[35m'; C_CYAN=$'\033[36m'
  C_GRAY=$'\033[90m'
  C_BRED=$'\033[91m';  C_BGREEN=$'\033[92m'; C_BYELLOW=$'\033[93m'
  C_BBLUE=$'\033[94m'; C_BCYAN=$'\033[96m'
else
  C_RESET=''; C_BOLD=''; C_DIM=''
  C_RED=''; C_GREEN=''; C_YELLOW=''; C_BLUE=''; C_MAGENTA=''; C_CYAN=''; C_GRAY=''
  C_BRED=''; C_BGREEN=''; C_BYELLOW=''; C_BBLUE=''; C_BCYAN=''
fi

# --- primitives --------------------------------------------------------------
__sweep_ts() { date +%H:%M:%S; }

# Repeat a character N times without depending on seq/printf-%.0s quirks.
__sweep_rule_str() {
  local width="${1:-72}" ch="${2:-─}" out='' i=0
  while [ "$i" -lt "$width" ]; do out="$out$ch"; i=$((i + 1)); done
  printf '%s' "$out"
}

# --- public helpers ----------------------------------------------------------
log_info()  { printf '%s%s%s %sℹ%s  %s\n'  "$C_GRAY" "$(__sweep_ts)" "$C_RESET" "$C_CYAN"   "$C_RESET" "$*"; }
log_ok()    { printf '%s%s%s %s✓%s  %s\n'  "$C_GRAY" "$(__sweep_ts)" "$C_RESET" "$C_BGREEN" "$C_RESET" "$*"; }
log_warn()  { printf '%s%s%s %s⚠%s  %s\n'  "$C_GRAY" "$(__sweep_ts)" "$C_RESET" "$C_BYELLOW" "$C_RESET" "$C_YELLOW$*$C_RESET"; }
log_step()  { printf '%s%s%s %s▶%s  %s\n'  "$C_GRAY" "$(__sweep_ts)" "$C_RESET" "$C_BBLUE"  "$C_RESET" "$*"; }
# Errors go to stderr (still captured by `... 2>&1` redirections).
log_error() { printf '%s%s%s %s✗  %s%s\n' "$C_GRAY" "$(__sweep_ts)" "$C_RESET" "$C_BRED" "$*" "$C_RESET" >&2; }

log_kv() {
  # log_kv "key" "value"
  printf '    %s%-14s%s %s\n' "$C_CYAN" "$1" "$C_RESET" "$2"
}

log_rule() {
  local title="${1:-}" width=74
  if [ -z "$title" ]; then
    printf '%s%s%s\n' "$C_GRAY" "$(__sweep_rule_str "$width")" "$C_RESET"
  else
    local dashlen=$(( width - ${#title} - 3 ))
    [ "$dashlen" -lt 0 ] && dashlen=0
    printf '%s── %s%s%s %s%s\n' "$C_GRAY" "$C_BOLD$title$C_RESET" "$C_GRAY" '' "$(__sweep_rule_str "$dashlen")" "$C_RESET"
  fi
}

log_banner() {
  # Boxed section header (double rule).
  local title="$1" width=74 bar
  bar="$(__sweep_rule_str "$width" '═')"
  printf '%s╔%s╗%s\n' "$C_BBLUE" "$bar" "$C_RESET"
  printf '%s║%s %s%-*s%s %s║%s\n' \
    "$C_BBLUE" "$C_RESET" "$C_BOLD" "$((width - 2))" "$title" "$C_RESET" "$C_BBLUE" "$C_RESET"
  printf '%s╚%s╝%s\n' "$C_BBLUE" "$bar" "$C_RESET"
}

fmt_elapsed() {
  local s="${1:-0}" h m
  h=$(( s / 3600 )); m=$(( (s % 3600) / 60 )); s=$(( s % 60 ))
  if   [ "$h" -gt 0 ]; then printf '%dh%02dm%02ds' "$h" "$m" "$s"
  elif [ "$m" -gt 0 ]; then printf '%dm%02ds' "$m" "$s"
  else                      printf '%ds' "$s"
  fi
}

log_since() {
  # log_since "message" <start_epoch>
  local msg="$1" start="${2:-}" now
  now="$(date +%s)"
  if [ -n "$start" ]; then
    log_ok "$msg ${C_DIM}(took $(fmt_elapsed $(( now - start ))))${C_RESET}"
  else
    log_ok "$msg"
  fi
}
