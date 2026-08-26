#!/usr/bin/env bash
# lib/constants.sh — Colors, status constants, section metadata
# Part of cisaudit — Linux CIS Hardening Auditor

# ── Version & Benchmark ────────────────────────────────────────────────────────
CISAUDIT_VERSION="1.0.0"
BENCHMARK_ID="CIS Debian Linux 12 Benchmark v1.1.0"
BENCHMARK_DATE="2024-01-01"

# ── Status constants ───────────────────────────────────────────────────────────
STATUS_PASS="PASS"
STATUS_FAIL="FAIL"
STATUS_WARN="WARN"
STATUS_SKIP="SKIP"

# ── ANSI Colors ────────────────────────────────────────────────────────────────
if [[ "${NO_COLOR:-}" == "1" ]] || [[ ! -t 1 && "${FORCE_COLOR:-}" != "1" ]]; then
  RED=""; GREEN=""; YELLOW=""; BLUE=""; CYAN=""; MAGENTA=""
  BOLD=""; DIM=""; RESET=""
  BG_RED=""; BG_GREEN=""; BG_YELLOW=""; BG_BLUE=""
else
  RED="\033[0;31m"
  GREEN="\033[0;32m"
  YELLOW="\033[0;33m"
  BLUE="\033[0;34m"
  MAGENTA="\033[0;35m"
  CYAN="\033[0;36m"
  BOLD="\033[1m"
  DIM="\033[2m"
  RESET="\033[0m"
  BG_RED="\033[41m"
  BG_GREEN="\033[42m"
  BG_YELLOW="\033[43m"
  BG_BLUE="\033[44m"
fi

# ── Status color helpers ───────────────────────────────────────────────────────
color_status() {
  local status="$1"
  case "$status" in
    PASS) echo -e "${GREEN}${BOLD}PASS${RESET}" ;;
    FAIL) echo -e "${RED}${BOLD}FAIL${RESET}" ;;
    WARN) echo -e "${YELLOW}${BOLD}WARN${RESET}" ;;
    SKIP) echo -e "${DIM}SKIP${RESET}" ;;
    *)    echo "$status" ;;
  esac
}

# ── CIS Sections ──────────────────────────────────────────────────────────────
# Ordered list used for report rendering
SECTIONS=(
  "initial_setup"
  "services"
  "network"
  "logging"
  "access"
  "maintenance"
)

# Human-readable section names
declare -A SECTION_NAMES=(
  ["initial_setup"]="Initial Setup"
  ["services"]="Services"
  ["network"]="Network Configuration"
  ["logging"]="Logging & Auditing"
  ["access"]="Access, Authentication & Authorization"
  ["maintenance"]="System Maintenance"
)
