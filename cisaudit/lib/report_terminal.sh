#!/usr/bin/env bash
# lib/report_terminal.sh — Pretty terminal report renderer
# Part of cisaudit — Linux CIS Hardening Auditor

# ── Progress bar helper ───────────────────────────────────────────────────────
# progress_bar <percent_float> <width>  → prints a filled ASCII bar
progress_bar() {
  local pct="$1"
  local width="${2:-30}"
  local filled
  filled=$(awk -v p="$pct" -v w="$width" 'BEGIN { printf "%d", p/100*w }')
  local empty=$(( width - filled ))

  local bar=""
  local color
  if awk -v p="$pct" 'BEGIN { exit !(p >= 80) }'; then
    color="$GREEN"
  elif awk -v p="$pct" 'BEGIN { exit !(p >= 50) }'; then
    color="$YELLOW"
  else
    color="$RED"
  fi

  bar="${color}${BOLD}"
  for (( i=0; i<filled; i++ )); do bar+="█"; done
  bar+="${RESET}${DIM}"
  for (( i=0; i<empty; i++ )); do bar+="░"; done
  bar+="${RESET}"

  echo -en "$bar"
}

# ── Badge helpers ─────────────────────────────────────────────────────────────
status_badge() {
  local status="$1"
  case "$status" in
    PASS) echo -e " ${GREEN}${BOLD}[PASS]${RESET} " ;;
    FAIL) echo -e " ${RED}${BOLD}[FAIL]${RESET} " ;;
    WARN) echo -e " ${YELLOW}${BOLD}[WARN]${RESET} " ;;
    SKIP) echo -e " ${DIM}[SKIP]${RESET} " ;;
    *)    echo -e " [${status}] " ;;
  esac
}

# ── Banner ────────────────────────────────────────────────────────────────────
print_banner() {
  echo -e ""
  echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════════════════╗${RESET}"
  echo -e "${CYAN}${BOLD}║         🔒  Linux CIS Hardening Auditor  🔒                 ║${RESET}"
  echo -e "${CYAN}${BOLD}║              cisaudit v${CISAUDIT_VERSION}                               ║${RESET}"
  echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════════════════╝${RESET}"
  echo -e "${DIM}   Benchmark: ${BENCHMARK_ID}${RESET}"
  if [[ "$SYSROOT" != "/" ]]; then
    echo -e "${YELLOW}   Mode: TEST  (SYSROOT=${SYSROOT})${RESET}"
  else
    echo -e "${GREEN}   Mode: LIVE  (auditing running system)${RESET}"
  fi
  echo -e "${DIM}   Host: $(hostname 2>/dev/null || echo "unknown")  |  Date: $(date '+%Y-%m-%d %H:%M:%S')${RESET}"
  echo ""
}

# ── Summary cards ─────────────────────────────────────────────────────────────
print_summary() {
  echo -e "${BOLD}━━━ OVERALL SCORE ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  echo ""

  # Overall score with big colored number
  local score_color
  if awk -v s="$SCORE_OVERALL" 'BEGIN { exit !(s >= 80) }'; then
    score_color="$GREEN"
  elif awk -v s="$SCORE_OVERALL" 'BEGIN { exit !(s >= 50) }'; then
    score_color="$YELLOW"
  else
    score_color="$RED"
  fi

  echo -e "  Score:  ${score_color}${BOLD}${SCORE_OVERALL}%${RESET}   $(progress_bar "$SCORE_OVERALL" 40)"
  echo ""
  echo -e "  ${GREEN}${BOLD}PASS${RESET} ${TOTAL_PASS}   ${RED}${BOLD}FAIL${RESET} ${TOTAL_FAIL}   ${YELLOW}${BOLD}WARN${RESET} ${TOTAL_WARN}   ${DIM}SKIP${RESET} ${TOTAL_SKIP}   Total: ${TOTAL_CONTROLS}"
  echo ""
  echo -e "  Level 1: ${BOLD}${SCORE_BY_LEVEL[1]:-N/A}%${RESET}   Level 2: ${BOLD}${SCORE_BY_LEVEL[2]:-N/A}%${RESET}"
  echo ""
}

# ── Section table ─────────────────────────────────────────────────────────────
print_section_table() {
  echo -e "${BOLD}━━━ SECTION SCORES ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  echo ""
  printf "  %-40s  %6s  %4s  %4s  %4s  %4s  %-28s\n" \
    "Section" "Score" "PASS" "FAIL" "WARN" "SKIP" "Progress"
  echo -e "  ${DIM}$(printf '%.0s─' {1..100})${RESET}"

  for section in "${SECTIONS[@]}"; do
    local name="${SECTION_NAMES[$section]:-$section}"
    local score="${SECTION_SCORE[$section]:-0.0}"
    local sp="${SECTION_PASS[$section]:-0}"
    local sf="${SECTION_FAIL[$section]:-0}"
    local sw="${SECTION_WARN[$section]:-0}"
    local sk="${SECTION_SKIP[$section]:-0}"
    local total="${SECTION_TOTAL[$section]:-0}"

    # Only print sections that have controls
    (( total > 0 )) || continue

    printf "  %-40s  %5s%%  %4s  %4s  %4s  %4s  " \
      "${name:0:40}" "$score" "$sp" "$sf" "$sw" "$sk"
    progress_bar "$score" 24
    echo ""
  done
  echo ""
}

# ── Per-control detail ────────────────────────────────────────────────────────
print_controls() {
  local show_pass="${SHOW_PASS:-1}"    # 1=show, 0=failures only
  local current_section=""

  echo -e "${BOLD}━━━ CONTROL RESULTS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  echo ""

  for id in "${RESULT_ORDER[@]}"; do
    local status="${RESULT_STATUS[$id]:-SKIP}"
    local section="${CTRL_SECTION[$id]}"
    local title="${CTRL_TITLE[$id]}"
    local level="${CTRL_LEVEL[$id]}"
    local evidence="${RESULT_EVIDENCE[$id]}"
    local fix="${CTRL_REMEDIATION[$id]}"

    # Section header when section changes
    if [[ "$section" != "$current_section" ]]; then
      current_section="$section"
      echo -e "  ${CYAN}${BOLD}▶ ${SECTION_NAMES[$section]:-$section}${RESET}"
      echo ""
    fi

    # Skip PASS/SKIP details in compact mode (show_pass=0)
    if [[ "$show_pass" == "0" && ("$status" == "PASS" || "$status" == "SKIP") ]]; then
      continue
    fi

    # Control line
    printf "  %s %-8s [L%s] %s\n" \
      "$(status_badge "$status")" "$id" "$level" "$title"

    # Evidence + remediation only for non-PASS
    if [[ "$status" == "FAIL" || "$status" == "WARN" ]]; then
      if [[ -n "$evidence" ]]; then
        echo -e "          ${DIM}Evidence:    ${evidence}${RESET}"
      fi
      if [[ -n "$fix" ]]; then
        echo -e "          ${YELLOW}Remediation: ${fix}${RESET}"
      fi
      echo ""
    elif [[ "$status" == "PASS" && -n "$evidence" ]]; then
      echo -e "          ${DIM}${evidence}${RESET}"
    elif [[ "$status" == "SKIP" ]]; then
      echo -e "          ${DIM}${evidence:-Skipped in test mode or insufficient privileges}${RESET}"
    fi
  done
  echo ""
}

# ── Footer ────────────────────────────────────────────────────────────────────
print_footer() {
  echo -e "${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  echo -e "${DIM}  cisaudit v${CISAUDIT_VERSION} | ${BENCHMARK_ID}${RESET}"
  echo -e "${DIM}  WARNING: Passing all controls ≠ unbreakable. Hardening reduces${RESET}"
  echo -e "${DIM}  blast radius; defense-in-depth is required.${RESET}"
  echo -e "${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  echo ""
}

# ── Main entry point ──────────────────────────────────────────────────────────
emit_terminal_report() {
  print_banner
  print_summary
  print_section_table
  print_controls
  print_footer
}
