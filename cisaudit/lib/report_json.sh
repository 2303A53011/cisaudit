#!/usr/bin/env bash
# lib/report_json.sh — Machine-readable JSON report
# Part of cisaudit — Linux CIS Hardening Auditor
#
# Hand-rolled JSON — no jq dependency.
# This is intentional: the tool must run on a minimal Debian install.

# ── JSON escaping ─────────────────────────────────────────────────────────────
# json_escape <string>  — escape the 5 JSON special characters
json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"   # backslash first
  s="${s//\"/\\\"}"   # double-quote
  s="${s//$'\n'/\\n}" # newline
  s="${s//$'\r'/\\r}" # carriage return
  s="${s//$'\t'/\\t}" # tab
  echo -n "$s"
}

# ── Main entry point ──────────────────────────────────────────────────────────
emit_json_report() {
  local out=""

  # ── Metadata block ─────────────────────────────────────────────────────────
  out+='{'$'\n'
  out+='  "cisaudit_version": "'"$(json_escape "$CISAUDIT_VERSION")"'",'$'\n'
  out+='  "benchmark": "'"$(json_escape "$BENCHMARK_ID")"'",'$'\n'
  out+='  "hostname": "'"$(json_escape "$(hostname 2>/dev/null || echo unknown)")"'",'$'\n'
  out+='  "sysroot": "'"$(json_escape "$SYSROOT")"'",'$'\n'
  out+='  "timestamp": "'"$(date -u '+%Y-%m-%dT%H:%M:%SZ')"'",'$'\n'

  # ── Summary block ──────────────────────────────────────────────────────────
  out+='  "summary": {'$'\n'
  out+='    "total_controls": '"$TOTAL_CONTROLS"','$'\n'
  out+='    "pass": '"$TOTAL_PASS"','$'\n'
  out+='    "fail": '"$TOTAL_FAIL"','$'\n'
  out+='    "warn": '"$TOTAL_WARN"','$'\n'
  out+='    "skip": '"$TOTAL_SKIP"','$'\n'
  out+='    "score_overall": '"$SCORE_OVERALL"','$'\n'
  out+='    "score_level_1": "'"$(json_escape "${SCORE_BY_LEVEL[1]:-N/A}")"'",'$'\n'
  out+='    "score_level_2": "'"$(json_escape "${SCORE_BY_LEVEL[2]:-N/A}")"'"'$'\n'
  out+='  },'$'\n'

  # ── Section scores ─────────────────────────────────────────────────────────
  out+='  "section_scores": {'$'\n'
  local first_section=1
  for section in "${SECTIONS[@]}"; do
    local total="${SECTION_TOTAL[$section]:-0}"
    (( total > 0 )) || continue
    [[ "$first_section" == "1" ]] || out+=','$'\n'
    first_section=0
    out+='    "'"$(json_escape "$section")"'": {'$'\n'
    out+='      "name": "'"$(json_escape "${SECTION_NAMES[$section]:-$section}")"'",'$'\n'
    out+='      "score": '"${SECTION_SCORE[$section]:-0.0}"','$'\n'
    out+='      "pass": '"${SECTION_PASS[$section]:-0}"','$'\n'
    out+='      "fail": '"${SECTION_FAIL[$section]:-0}"','$'\n'
    out+='      "warn": '"${SECTION_WARN[$section]:-0}"','$'\n'
    out+='      "skip": '"${SECTION_SKIP[$section]:-0}"''$'\n'
    out+='    }'
  done
  out+=$'\n''  },'$'\n'

  # ── Controls array ─────────────────────────────────────────────────────────
  out+='  "controls": ['$'\n'
  local first_ctrl=1
  for id in "${RESULT_ORDER[@]}"; do
    [[ "$first_ctrl" == "1" ]] || out+=','$'\n'
    first_ctrl=0
    local status="${RESULT_STATUS[$id]:-SKIP}"
    local evidence="${RESULT_EVIDENCE[$id]:-}"
    local section="${CTRL_SECTION[$id]:-}"
    local title="${CTRL_TITLE[$id]:-}"
    local level="${CTRL_LEVEL[$id]:-1}"
    local scored="${CTRL_SCORED[$id]:-yes}"
    local fix="${CTRL_REMEDIATION[$id]:-}"
    local desc="${CTRL_DESCRIPTION[$id]:-}"

    out+='    {'$'\n'
    out+='      "id": "'"$(json_escape "$id")"'",'$'\n'
    out+='      "section": "'"$(json_escape "$section")"'",'$'\n'
    out+='      "level": '"$level"','$'\n'
    out+='      "scored": '"$( [[ "$scored" == "yes" ]] && echo "true" || echo "false" )"','$'\n'
    out+='      "title": "'"$(json_escape "$title")"'",'$'\n'
    out+='      "description": "'"$(json_escape "$desc")"'",'$'\n'
    out+='      "status": "'"$(json_escape "$status")"'",'$'\n'
    out+='      "evidence": "'"$(json_escape "$evidence")"'",'$'\n'
    out+='      "remediation": "'"$(json_escape "$fix")"'"'$'\n'
    out+='    }'
  done
  out+=$'\n''  ]'$'\n'
  out+='}'

  echo "$out"
}
