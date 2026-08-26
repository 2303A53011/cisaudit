#!/usr/bin/env bash
# cisaudit.sh — Linux CIS Hardening Auditor
# Entry point: CLI parsing, module loading, orchestration
#
# Usage:
#   cisaudit                          Run against live system, terminal output
#   cisaudit -t <dir>                 Run in test mode against mock filesystem
#   cisaudit -f json|html|terminal    Choose output format
#   cisaudit -o <file>                Write output to file instead of stdout
#   cisaudit -l 1|2                   Restrict to CIS Level 1 or 2 controls
#   cisaudit --baseline <file>        Save this run as a baseline
#   cisaudit --diff <file>            Compare this run against a saved baseline
#   cisaudit --summary                Print summary only (no per-control detail)
#   cisaudit --no-color               Disable ANSI color output
#   cisaudit --failures-only          Show only FAIL/WARN controls in terminal report
#   cisaudit --version                Print version and exit
#   cisaudit --help                   Print usage and exit

set -euo pipefail

# ── Resolve script location ───────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Defaults ──────────────────────────────────────────────────────────────────
SYSROOT="/"
OPT_FORMAT="terminal"
OPT_OUTPUT=""        # empty = stdout
OPT_LEVEL=""         # empty = all levels
OPT_BASELINE_SAVE="" # file to save baseline to
OPT_BASELINE_DIFF="" # file to diff against
SHOW_PASS="1"        # 1 = show PASS controls, 0 = failures-only

# ── Bash version guard ────────────────────────────────────────────────────────
if (( BASH_VERSINFO[0] < 4 )); then
  echo "ERROR: cisaudit requires Bash 4+. Current version: $BASH_VERSION" >&2
  echo "  On macOS: brew install bash && exec /usr/local/bin/bash $0 $*" >&2
  exit 1
fi

# ── Usage ─────────────────────────────────────────────────────────────────────
usage() {
  cat <<EOF
cisaudit v${CISAUDIT_VERSION:-1.0.0} — Linux CIS Hardening Auditor

USAGE:
  cisaudit [OPTIONS]

OPTIONS:
  -t, --test <dir>         Run in test mode against a mock filesystem directory
  -f, --format <fmt>       Output format: terminal (default), json, html
  -o, --output <file>      Write output to file (default: stdout)
  -l, --level <1|2>        Restrict to CIS Level 1 or Level 2 controls
  --baseline <file>        Save this run's JSON output as a named baseline
  --diff <file>            Compare this run against a saved baseline file
  --summary                Print summary scores only (no per-control detail)
  --failures-only          Show only FAIL/WARN controls in terminal report
  --no-color               Disable ANSI color output (also: NO_COLOR=1)
  --version                Print version and exit
  -h, --help               Print this help and exit

EXAMPLES:
  # Audit live system with terminal output
  sudo cisaudit

  # Run in test mode (no root required)
  cisaudit -t testdata/fixtures

  # Generate HTML report
  sudo cisaudit -f html -o report.html && xdg-open report.html

  # Save a baseline then compare after changes
  sudo cisaudit -f json --baseline baseline.json
  sudo cisaudit --diff baseline.json

  # CI mode: exit non-zero if score < threshold
  sudo cisaudit -f json -o /dev/null; echo "Exit: \$?"

EOF
}

# ── CLI Argument parsing ──────────────────────────────────────────────────────
parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -t|--test)
        SYSROOT="${2:?--test requires a directory argument}"
        shift 2
        ;;
      -f|--format)
        OPT_FORMAT="${2:?--format requires: terminal|json|html}"
        shift 2
        ;;
      -o|--output)
        OPT_OUTPUT="${2:?--output requires a file path}"
        shift 2
        ;;
      -l|--level)
        OPT_LEVEL="${2:?--level requires 1 or 2}"
        shift 2
        ;;
      --baseline)
        OPT_BASELINE_SAVE="${2:?--baseline requires a file path}"
        shift 2
        ;;
      --diff)
        OPT_BASELINE_DIFF="${2:?--diff requires a file path}"
        shift 2
        ;;
      --summary)
        # Handled in report_terminal.sh via SHOW_PASS
        SHOW_PASS="0"
        shift
        ;;
      --failures-only)
        SHOW_PASS="0"
        shift
        ;;
      --no-color)
        NO_COLOR=1
        shift
        ;;
      --version)
        # Load constants first to get version
        source "${SCRIPT_DIR}/lib/constants.sh"
        echo "cisaudit v${CISAUDIT_VERSION}"
        exit 0
        ;;
      -h|--help)
        source "${SCRIPT_DIR}/lib/constants.sh"
        usage
        exit 0
        ;;
      *)
        echo "Unknown option: $1  (use --help for usage)" >&2
        exit 1
        ;;
    esac
  done
}

# ── Module loader ─────────────────────────────────────────────────────────────
load_modules() {
  source "${SCRIPT_DIR}/lib/constants.sh"
  source "${SCRIPT_DIR}/lib/utils.sh"
  source "${SCRIPT_DIR}/lib/registry.sh"
  source "${SCRIPT_DIR}/controls/registry_data.sh"   # populates CTRL_* arrays
  source "${SCRIPT_DIR}/lib/engine.sh"
  source "${SCRIPT_DIR}/lib/report_terminal.sh"
  source "${SCRIPT_DIR}/lib/report_json.sh"
  source "${SCRIPT_DIR}/lib/report_html.sh"
  source "${SCRIPT_DIR}/lib/baseline.sh"

  # Load check functions (one file per CIS section)
  source "${SCRIPT_DIR}/checks/01_initial_setup.sh"
  # Future sections will be sourced here:
  # source "${SCRIPT_DIR}/checks/02_services.sh"
  # source "${SCRIPT_DIR}/checks/03_network.sh"
}

# ── Validate SYSROOT ──────────────────────────────────────────────────────────
validate_sysroot() {
  if [[ "$SYSROOT" != "/" && ! -d "$SYSROOT" ]]; then
    echo "ERROR: Test directory does not exist: $SYSROOT" >&2
    exit 1
  fi
  # Normalise: always ends with /
  SYSROOT="${SYSROOT%/}/"
  export SYSROOT
}

# ── Run all checks ────────────────────────────────────────────────────────────
run_all_checks() {
  for id in "${REGISTERED_IDS[@]}"; do
    # Filter by level if requested
    if [[ -n "$OPT_LEVEL" ]]; then
      local ctrl_level="${CTRL_LEVEL[$id]:-1}"
      [[ "$ctrl_level" == "$OPT_LEVEL" ]] || continue
    fi

    # Derive function name from control ID
    local fn_name
    fn_name="$(get_check_fn_name "$id")"

    if declare -f "$fn_name" > /dev/null; then
      "$fn_name"
    else
      # No check function registered — mark as SKIP
      record_result "$id" "$STATUS_SKIP" "Check function '$fn_name' not implemented"
    fi
  done
}

# ── Generate report ───────────────────────────────────────────────────────────
generate_report() {
  local format="$OPT_FORMAT"
  local outfile="$OPT_OUTPUT"

  _emit() {
    case "$format" in
      terminal) emit_terminal_report ;;
      json)     emit_json_report ;;
      html)     emit_html_report ;;
      *)
        echo "Unknown format '$format'. Use: terminal, json, html" >&2
        exit 1
        ;;
    esac
  }

  if [[ -n "$outfile" ]]; then
    _emit > "$outfile"
    echo "Report written to: $outfile" >&2
  else
    _emit
  fi
}

# ── Exit code ─────────────────────────────────────────────────────────────────
# Returns 0 if score >= 80%, 1 otherwise (useful for CI gating)
compute_exit_code() {
  if awk -v s="$SCORE_OVERALL" 'BEGIN { exit !(s >= 80) }'; then
    return 0
  else
    return 1
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
main() {
  parse_args "$@"
  load_modules
  validate_sysroot

  # Warn if not root on live system
  if [[ "$SYSROOT" == "/" && "$(id -u)" != "0" ]]; then
    echo -e "${YELLOW}WARNING: Not running as root. Some checks will SKIP due to permission restrictions.${RESET}" >&2
    echo -e "${YELLOW}         Run with: sudo cisaudit${RESET}" >&2
    echo "" >&2
  fi

  # Run all registered checks
  run_all_checks

  # Aggregate scores
  compute_scores

  # Baseline diff (before printing report, since diff uses terminal output)
  if [[ -n "$OPT_BASELINE_DIFF" ]]; then
    diff_baseline "$OPT_BASELINE_DIFF"
  fi

  # Generate and output report
  generate_report

  # Save baseline if requested
  if [[ -n "$OPT_BASELINE_SAVE" ]]; then
    save_baseline "$OPT_BASELINE_SAVE"
  fi

  # Exit with score-based code for CI use
  compute_exit_code
}

main "$@"
