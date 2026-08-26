#!/usr/bin/env bash
# lib/registry.sh — In-memory control registry and result store
# Part of cisaudit — Linux CIS Hardening Auditor
#
# Two write paths:
#   register_control()  — called at startup from controls/registry_data.sh
#   record_result()     — called at runtime by each check_X_X_X() function
#
# Everything else (engine, reporters, baseline) reads from these arrays.

# ── Registry data model ───────────────────────────────────────────────────────
declare -gA CTRL_TITLE=()
declare -gA CTRL_SECTION=()
declare -gA CTRL_LEVEL=()
declare -gA CTRL_SCORED=()
declare -gA CTRL_DESCRIPTION=()
declare -gA CTRL_REMEDIATION=()

# Ordered list of registered IDs (insertion order)
declare -ga REGISTERED_IDS=()

# ── Result data model ─────────────────────────────────────────────────────────
declare -gA RESULT_STATUS=()
declare -gA RESULT_EVIDENCE=()
declare -ga RESULT_ORDER=()   # execution order (may differ from registration order)

# ── register_control ──────────────────────────────────────────────────────────
# Usage:
#   register_control \
#     --id       "1.1.1.1" \
#     --section  "1_initial_setup" \
#     --level    "1" \
#     --scored   "yes" \
#     --title    "Ensure mounting of cramfs filesystems is disabled" \
#     --desc     "Short description..." \
#     --fix      "echo 'install cramfs /bin/false' >> /etc/modprobe.d/cisaudit.conf"

register_control() {
  local id="" section="" level="" scored="" title="" desc="" fix=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --id)      id="$2";      shift 2 ;;
      --section) section="$2"; shift 2 ;;
      --level)   level="$2";   shift 2 ;;
      --scored)  scored="$2";  shift 2 ;;
      --title)   title="$2";   shift 2 ;;
      --desc)    desc="$2";    shift 2 ;;
      --fix)     fix="$2";     shift 2 ;;
      *) echo "[registry] Unknown arg: $1" >&2; shift ;;
    esac
  done

  [[ -z "$id" ]] && { echo "[registry] register_control: --id required" >&2; return 1; }

  CTRL_TITLE["$id"]="$title"
  CTRL_SECTION["$id"]="$section"
  CTRL_LEVEL["$id"]="$level"
  CTRL_SCORED["$id"]="$scored"
  CTRL_DESCRIPTION["$id"]="$desc"
  CTRL_REMEDIATION["$id"]="$fix"

  REGISTERED_IDS+=("$id")
}

# ── record_result ──────────────────────────────────────────────────────────────
# Usage:
#   record_result "1.1.1.1" "PASS" "Module cramfs is blocked in /etc/modprobe.d/cramfs.conf"

record_result() {
  local id="$1"
  local status="$2"
  local evidence="${3:-}"

  RESULT_STATUS["$id"]="$status"
  RESULT_EVIDENCE["$id"]="$evidence"
  RESULT_ORDER+=("$id")
}

# ── get_check_fn_name ──────────────────────────────────────────────────────────
# Derives the check function name from a control ID.
# "1.1.1.1" → "check_1_1_1_1"
# Convention-over-configuration: no explicit dispatch table needed.

get_check_fn_name() {
  local id="$1"
  echo "check_${id//\./_}"
}
