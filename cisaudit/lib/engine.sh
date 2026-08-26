#!/usr/bin/env bash
# lib/engine.sh — Score aggregation
# Part of cisaudit — Linux CIS Hardening Auditor
#
# compute_scores() reads RESULT_STATUS[*] and CTRL_SECTION[*], populating:
#   SECTION_PASS, SECTION_FAIL, SECTION_WARN, SECTION_SKIP  (per-section counts)
#   SCORE_OVERALL  (float, 1 decimal)
#   SCORE_BY_LEVEL (float per level 1/2)
#   TOTAL_PASS, TOTAL_FAIL, TOTAL_WARN, TOTAL_SKIP, TOTAL_CONTROLS

# ── Per-section counters ──────────────────────────────────────────────────────
declare -gA SECTION_PASS=()
declare -gA SECTION_FAIL=()
declare -gA SECTION_WARN=()
declare -gA SECTION_SKIP=()
declare -gA SECTION_TOTAL=()
declare -gA SECTION_SCORE=()   # float percentage string

# ── Per-level counters ────────────────────────────────────────────────────────
declare -gA LEVEL_PASS=()
declare -gA LEVEL_FAIL=()
declare -gA LEVEL_SCORED_TOTAL=()
declare -gA SCORE_BY_LEVEL=()

# ── Overall totals ────────────────────────────────────────────────────────────
TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_WARN=0
TOTAL_SKIP=0
TOTAL_CONTROLS=0
SCORE_OVERALL="0.0"

# ── compute_scores ────────────────────────────────────────────────────────────
compute_scores() {
  # Reset all counters
  TOTAL_PASS=0; TOTAL_FAIL=0; TOTAL_WARN=0; TOTAL_SKIP=0; TOTAL_CONTROLS=0

  for section in "${SECTIONS[@]}"; do
    SECTION_PASS["$section"]=0
    SECTION_FAIL["$section"]=0
    SECTION_WARN["$section"]=0
    SECTION_SKIP["$section"]=0
    SECTION_TOTAL["$section"]=0
  done

  for lvl in 1 2; do
    LEVEL_PASS["$lvl"]=0
    LEVEL_FAIL["$lvl"]=0
    LEVEL_SCORED_TOTAL["$lvl"]=0
  done

  # Tally each result
  for id in "${REGISTERED_IDS[@]}"; do
    local status="${RESULT_STATUS[$id]:-SKIP}"
    local section="${CTRL_SECTION[$id]:-unknown}"
    local level="${CTRL_LEVEL[$id]:-1}"
    local scored="${CTRL_SCORED[$id]:-yes}"

    (( TOTAL_CONTROLS++ )) || true

    case "$status" in
      PASS)
        (( TOTAL_PASS++ )) || true
        (( SECTION_PASS["$section"]++ )) || true
        if [[ "$scored" == "yes" ]]; then
          (( LEVEL_PASS["$level"]++ )) || true
          (( LEVEL_SCORED_TOTAL["$level"]++ )) || true
        fi
        ;;
      FAIL)
        (( TOTAL_FAIL++ )) || true
        (( SECTION_FAIL["$section"]++ )) || true
        if [[ "$scored" == "yes" ]]; then
          (( LEVEL_FAIL["$level"]++ )) || true
          (( LEVEL_SCORED_TOTAL["$level"]++ )) || true
        fi
        ;;
      WARN)
        (( TOTAL_WARN++ )) || true
        (( SECTION_WARN["$section"]++ )) || true
        ;;
      SKIP)
        (( TOTAL_SKIP++ )) || true
        (( SECTION_SKIP["$section"]++ )) || true
        ;;
    esac

    (( SECTION_TOTAL["$section"]++ )) || true
  done

  # Compute overall score (PASS / (PASS+FAIL) * 100, ignoring WARN/SKIP)
  local scored_total=$(( TOTAL_PASS + TOTAL_FAIL ))
  if (( scored_total > 0 )); then
    SCORE_OVERALL=$(awk -v p="$TOTAL_PASS" -v t="$scored_total" 'BEGIN { printf "%.1f", p/t*100 }')
  else
    SCORE_OVERALL="0.0"
  fi

  # Compute per-section scores
  for section in "${SECTIONS[@]}"; do
    local sp="${SECTION_PASS[$section]:-0}"
    local sf="${SECTION_FAIL[$section]:-0}"
    local st=$(( sp + sf ))
    if (( st > 0 )); then
      SECTION_SCORE["$section"]=$(awk -v p="$sp" -v t="$st" 'BEGIN { printf "%.1f", p/t*100 }')
    else
      SECTION_SCORE["$section"]="0.0"
    fi
  done

  # Compute per-level scores
  for lvl in 1 2; do
    local lp="${LEVEL_PASS[$lvl]:-0}"
    local lt="${LEVEL_SCORED_TOTAL[$lvl]:-0}"
    if (( lt > 0 )); then
      SCORE_BY_LEVEL["$lvl"]=$(awk -v p="$lp" -v t="$lt" 'BEGIN { printf "%.1f", p/t*100 }')
    else
      SCORE_BY_LEVEL["$lvl"]="N/A"
    fi
  done
}
