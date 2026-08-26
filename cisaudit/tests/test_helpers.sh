#!/usr/bin/env bash
# tests/test_helpers.sh — Test assertion helpers
# Part of cisaudit — Linux CIS Hardening Auditor
#
# Sourced by each test_*.sh file inside a subshell.
# Provides: setup_test, assert_status, assert_evidence_contains, run_all_test_cases

# Per-subshell counters
_TEST_PASS=0
_TEST_FAIL=0
_TEST_SKIP=0

# ── Colors ────────────────────────────────────────────────────────────────────
GREEN="\033[0;32m"; RED="\033[0;31m"; DIM="\033[2m"; RESET="\033[0m"

# ── setup_test ────────────────────────────────────────────────────────────────
# Load cisaudit modules with a given SYSROOT (fixtures dir)
# Must be called at the start of each test case.
setup_test() {
  local sysroot="$1"
  export SYSROOT="${sysroot%/}/"

  # Source all modules fresh
  local dir
  dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  source "${dir}/lib/constants.sh"
  source "${dir}/lib/utils.sh"
  source "${dir}/lib/registry.sh"
  source "${dir}/controls/registry_data.sh"
  source "${dir}/lib/engine.sh"
  source "${dir}/lib/report_terminal.sh"
  source "${dir}/lib/report_json.sh"
  source "${dir}/lib/report_html.sh"
  source "${dir}/lib/baseline.sh"
  source "${dir}/checks/01_initial_setup.sh"

  # Clear all result/registry state
  REGISTERED_IDS=()
  RESULT_ORDER=()
  RESULT_STATUS=()
  RESULT_EVIDENCE=()
}

# ── run_single_check ──────────────────────────────────────────────────────────
# Re-registers and re-runs a single control in isolation.
run_single_check() {
  local id="$1"
  local fn
  fn="$(get_check_fn_name "$id")"
  if declare -f "$fn" > /dev/null; then
    "$fn"
  else
    record_result "$id" "SKIP" "No check function: $fn"
  fi
}

# ── assert_status ─────────────────────────────────────────────────────────────
# assert_status <control_id> <expected_status> [description]
assert_status() {
  local id="$1"
  local expected="$2"
  local desc="${3:-Control $id should be $expected}"
  local actual="${RESULT_STATUS[$id]:-NOT_RUN}"

  if [[ "$actual" == "$expected" ]]; then
    echo -e "    ${GREEN}✓${RESET} $desc"
    (( _TEST_PASS++ )) || true
  else
    echo -e "    ${RED}✗${RESET} $desc"
    echo -e "      ${RED}expected: $expected | got: $actual${RESET}"
    if [[ -n "${RESULT_EVIDENCE[$id]:-}" ]]; then
      echo -e "      ${DIM}evidence: ${RESULT_EVIDENCE[$id]}${RESET}"
    fi
    (( _TEST_FAIL++ )) || true
  fi
}

# ── assert_evidence_contains ──────────────────────────────────────────────────
# assert_evidence_contains <control_id> <substring> [description]
assert_evidence_contains() {
  local id="$1"
  local substring="$2"
  local desc="${3:-Evidence for $id should contain '$substring'}"
  local evidence="${RESULT_EVIDENCE[$id]:-}"

  if [[ "$evidence" == *"$substring"* ]]; then
    echo -e "    ${GREEN}✓${RESET} $desc"
    (( _TEST_PASS++ )) || true
  else
    echo -e "    ${RED}✗${RESET} $desc"
    echo -e "      ${RED}looking for: '$substring'${RESET}"
    echo -e "      ${RED}actual evidence: '${evidence}'${RESET}"
    (( _TEST_FAIL++ )) || true
  fi
}

# ── run_all_test_cases ────────────────────────────────────────────────────────
# Called by test_runner.sh — discovers and runs all test_case_* functions
run_all_test_cases() {
  local funcs
  funcs=$(declare -F | awk '{print $3}' | grep '^test_case_' | sort)
  for fn in $funcs; do
    echo -e "  ${DIM}Running: $fn${RESET}"
    "$fn"
  done
}
