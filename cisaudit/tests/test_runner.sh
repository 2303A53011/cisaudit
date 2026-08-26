#!/usr/bin/env bash
# tests/test_runner.sh — cisaudit test runner
# Part of cisaudit — Linux CIS Hardening Auditor
#
# Usage:
#   bash tests/test_runner.sh            Run all tests
#   bash tests/test_runner.sh -v         Verbose (show PASS details too)
#   bash tests/test_runner.sh test_01    Run only matching test files

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
VERBOSE="${VERBOSE:-0}"

# ── Counters ──────────────────────────────────────────────────────────────────
TESTS_PASS=0
TESTS_FAIL=0
TESTS_SKIP=0

# ── Colors ────────────────────────────────────────────────────────────────────
GREEN="\033[0;32m"; RED="\033[0;31m"; YELLOW="\033[0;33m"
CYAN="\033[0;36m"; BOLD="\033[1m"; DIM="\033[2m"; RESET="\033[0m"

# ── Print helpers ─────────────────────────────────────────────────────────────
pass() { echo -e "  ${GREEN}✓${RESET} $1"; (( TESTS_PASS++ )) || true; }
fail() { echo -e "  ${RED}✗${RESET} $1"; (( TESTS_FAIL++ )) || true; }
skip() { echo -e "  ${DIM}○${RESET} $1 ${DIM}(skipped)${RESET}"; (( TESTS_SKIP++ )) || true; }

# ── Test runner ───────────────────────────────────────────────────────────────
run_test_file() {
  local file="$1"
  echo ""
  echo -e "${CYAN}${BOLD}▶ $(basename "$file")${RESET}"

  # Source test helpers and the test file in a subshell for isolation
  # The subshell exports results via a temp file
  local tmpfile
  tmpfile="$(mktemp /tmp/cisaudit_test_XXXXXX)"

  (
    source "${SCRIPT_DIR}/test_helpers.sh"
    source "$file"
    run_all_test_cases
    echo "${_TEST_PASS}:${_TEST_FAIL}:${_TEST_SKIP}" > "$tmpfile"
  ) || {
    echo -e "  ${RED}ERROR: test file crashed — $file${RESET}"
    echo "0:1:0" > "$tmpfile"
  }

  local results
  results="$(cat "$tmpfile")"
  rm -f "$tmpfile"

  local p f s
  IFS=':' read -r p f s <<< "$results"
  (( TESTS_PASS += p )) || true
  (( TESTS_FAIL += f )) || true
  (( TESTS_SKIP += s )) || true
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
  local filter="${1:-}"
  echo ""
  echo -e "${BOLD}━━━ cisaudit Test Suite ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

  for test_file in "${SCRIPT_DIR}"/test_[0-9]*.sh; do
    [[ -f "$test_file" ]] || continue
    # Optional filter
    if [[ -n "$filter" && "$(basename "$test_file")" != *"$filter"* ]]; then
      continue
    fi
    run_test_file "$test_file"
  done

  echo ""
  echo -e "${BOLD}━━━ Results ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  echo -e "  ${GREEN}${BOLD}PASS${RESET}: $TESTS_PASS   ${RED}${BOLD}FAIL${RESET}: $TESTS_FAIL   ${DIM}SKIP${RESET}: $TESTS_SKIP"
  echo ""

  if (( TESTS_FAIL > 0 )); then
    echo -e "${RED}${BOLD}✗ $TESTS_FAIL test(s) failed${RESET}"
    exit 1
  else
    echo -e "${GREEN}${BOLD}✓ All tests passed!${RESET}"
    exit 0
  fi
}

main "$@"
