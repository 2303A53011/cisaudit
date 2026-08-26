#!/usr/bin/env bash
# lib/baseline.sh — Save and diff audit baselines
# Part of cisaudit — Linux CIS Hardening Auditor
#
# save_baseline <file>    — writes current JSON report to a baseline file
# diff_baseline <file>    — compares current results against a saved baseline

# ── save_baseline ─────────────────────────────────────────────────────────────
save_baseline() {
  local outfile="$1"
  emit_json_report > "$outfile"
  echo -e "${GREEN}Baseline saved → $outfile${RESET}" >&2
}

# ── diff_baseline ─────────────────────────────────────────────────────────────
# Reads a previously saved JSON baseline file and compares control statuses.
# Uses pure Bash regex parsing (no jq).

diff_baseline() {
  local baseline_file="$1"

  if [[ ! -r "$baseline_file" ]]; then
    echo "[baseline] Cannot read baseline file: $baseline_file" >&2
    return 1
  fi

  echo -e "${BOLD}━━━ BASELINE DRIFT REPORT ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  echo -e "${DIM}Comparing against: $baseline_file${RESET}"
  echo ""

  local regressions=0 improvements=0 unchanged=0

  # Parse baseline statuses using grep + awk (no jq)
  # Format in JSON: "id": "1.1.1.1", ... "status": "PASS"
  # We extract pairs by slurping the whole file and scanning for control blocks
  declare -A baseline_status=()
  local current_id=""
  while IFS= read -r line; do
    if [[ "$line" =~ \"id\":[[:space:]]*\"([^\"]+)\" ]]; then
      current_id="${BASH_REMATCH[1]}"
    fi
    if [[ -n "$current_id" && "$line" =~ \"status\":[[:space:]]*\"([^\"]+)\" ]]; then
      baseline_status["$current_id"]="${BASH_REMATCH[1]}"
      current_id=""
    fi
  done < "$baseline_file"

  for id in "${REGISTERED_IDS[@]}"; do
    local current="${RESULT_STATUS[$id]:-SKIP}"
    local prior="${baseline_status[$id]:-}"

    if [[ -z "$prior" ]]; then
      echo -e "  ${CYAN}[NEW]${RESET}        $id — ${CTRL_TITLE[$id]}"
      continue
    fi

    if [[ "$prior" == "$current" ]]; then
      (( unchanged++ )) || true
    elif [[ "$prior" == "PASS" && "$current" == "FAIL" ]]; then
      echo -e "  ${RED}${BOLD}[REGRESSION]${RESET} $id — ${CTRL_TITLE[$id]}"
      echo -e "               ${DIM}was PASS → now FAIL${RESET}"
      (( regressions++ )) || true
    elif [[ "$prior" == "FAIL" && "$current" == "PASS" ]]; then
      echo -e "  ${GREEN}${BOLD}[IMPROVED]${RESET}   $id — ${CTRL_TITLE[$id]}"
      echo -e "               ${DIM}was FAIL → now PASS${RESET}"
      (( improvements++ )) || true
    else
      echo -e "  ${YELLOW}[CHANGED]${RESET}    $id — ${CTRL_TITLE[$id]}"
      echo -e "               ${DIM}was $prior → now $current${RESET}"
    fi
  done

  echo ""
  echo -e "${BOLD}Drift summary:${RESET} ${RED}${regressions} regressions${RESET}  |  ${GREEN}${improvements} improvements${RESET}  |  ${DIM}${unchanged} unchanged${RESET}"
  echo ""
}
