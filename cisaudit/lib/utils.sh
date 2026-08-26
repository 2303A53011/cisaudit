#!/usr/bin/env bash
# lib/utils.sh — SYSROOT-aware system inspection primitives
# Part of cisaudit — Linux CIS Hardening Auditor
#
# Every function that touches the filesystem goes through ${SYSROOT}.
# When SYSROOT="/" → live system.  When SYSROOT="testdata/fixtures/" → test mode.
# This single abstraction makes 100% of checks testable without root.

# ── SYSROOT default ───────────────────────────────────────────────────────────
# Set by cisaudit.sh; defaulted here so utils.sh can be sourced standalone.
SYSROOT="${SYSROOT:-/}"

# Normalise: remove trailing slash then add it back → always ends with /
SYSROOT="${SYSROOT%/}/"

# ── Filesystem primitives ─────────────────────────────────────────────────────

# file_exists <path>  — path is relative to SYSROOT (no leading slash needed)
file_exists() {
  local path="${SYSROOT}${1#/}"
  [[ -e "$path" ]]
}

# read_file <path>  — cat a file under SYSROOT; returns "" if missing
read_file() {
  local path="${SYSROOT}${1#/}"
  if [[ -r "$path" ]]; then
    cat "$path"
  else
    echo ""
  fi
}

# file_contains <path> <pattern>  — grep -qE pattern in SYSROOT-relative file
file_contains() {
  local path="${SYSROOT}${1#/}"
  local pattern="$2"
  [[ -r "$path" ]] && grep -qE "$pattern" "$path"
}

# file_perm_octal <path>  — returns octal permissions, e.g. "644"
file_perm_octal() {
  local path="${SYSROOT}${1#/}"
  if [[ -e "$path" ]]; then
    stat -c "%a" "$path" 2>/dev/null || echo "000"
  else
    echo "000"
  fi
}

# file_owner <path>  — returns owner username
file_owner() {
  local path="${SYSROOT}${1#/}"
  if [[ -e "$path" ]]; then
    stat -c "%U" "$path" 2>/dev/null || echo "unknown"
  else
    echo "unknown"
  fi
}

# file_group <path>  — returns group name
file_group() {
  local path="${SYSROOT}${1#/}"
  if [[ -e "$path" ]]; then
    stat -c "%G" "$path" 2>/dev/null || echo "unknown"
  else
    echo "unknown"
  fi
}

# ── sysctl primitives ─────────────────────────────────────────────────────────
# In test mode: read from ${SYSROOT}/proc/sys/<param-as-path>
# In live mode: fall back to sysctl command

# param_to_path "kernel.randomize_va_space" → "kernel/randomize_va_space"
_sysctl_param_to_path() {
  echo "${1//\.//}"
}

get_sysctl() {
  local param="$1"
  local proc_path="${SYSROOT}proc/sys/$(_sysctl_param_to_path "$param")"
  if [[ -r "$proc_path" ]]; then
    cat "$proc_path"
  elif [[ "$SYSROOT" == "/" ]]; then
    sysctl -n "$param" 2>/dev/null || echo ""
  else
    echo ""
  fi
}

# ── Package helpers ───────────────────────────────────────────────────────────
# In test mode: check for a sentinel file under SYSROOT/var/lib/dpkg/info/<pkg>.list
# In live mode: use dpkg-query

package_is_installed() {
  local pkg="$1"
  if [[ "$SYSROOT" == "/" ]]; then
    dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"
  else
    # Test mode: sentinel file
    [[ -f "${SYSROOT}var/lib/dpkg/info/${pkg}.list" ]]
  fi
}

# ── Live-command gate ─────────────────────────────────────────────────────────
# run_cmd <cmd...> — run a live system command.
# SKIPS automatically in test mode (returns exit code 127, stdout="").
# Use for: systemctl, lsmod, iptables — commands that cannot be faked via files.

run_cmd() {
  if [[ "$SYSROOT" != "/" ]]; then
    # Test mode: refuse to shell out to live commands
    return 127
  fi
  "$@"
}

# service_is_enabled <service>  — returns 0 if service is enabled on live system
service_is_enabled() {
  run_cmd systemctl is-enabled "$1" 2>/dev/null | grep -q "enabled"
}

# service_is_active <service>  — returns 0 if service is running on live system
service_is_active() {
  run_cmd systemctl is-active "$1" 2>/dev/null | grep -q "^active$"
}

# ── Module helpers ────────────────────────────────────────────────────────────
# module_is_blocked <module>  — checks modprobe.d for "install <mod> /bin/false" or "blacklist <mod>"
module_is_blocked() {
  local mod="$1"
  local modprobe_dir="${SYSROOT}etc/modprobe.d"
  if [[ -d "$modprobe_dir" ]]; then
    grep -rqE "install\s+${mod}\s+/bin/(false|true)|blacklist\s+${mod}" "$modprobe_dir" 2>/dev/null
  else
    return 1
  fi
}

# module_is_loaded <module>  — only meaningful on live system
module_is_loaded() {
  local mod="$1"
  if [[ "$SYSROOT" == "/" ]]; then
    lsmod 2>/dev/null | awk '{print $1}' | grep -q "^${mod}$"
  else
    return 1  # Not loaded in test mode (safe assumption)
  fi
}

# ── fstab helpers ─────────────────────────────────────────────────────────────
# mount_option_set <mountpoint> <option>  — checks /etc/fstab for mount option
mount_option_set() {
  local mountpoint="$1"
  local option="$2"
  local fstab="${SYSROOT}etc/fstab"
  [[ -r "$fstab" ]] && awk -v mp="$mountpoint" -v opt="$option" '
    $1 !~ /^#/ && $2 == mp && $4 ~ opt { found=1 }
    END { exit !found }
  ' "$fstab"
}

# ── SSH config helpers ────────────────────────────────────────────────────────
# ssh_config_value <key>  — returns the value of a key in sshd_config
ssh_config_value() {
  local key="$1"
  local conf="${SYSROOT}etc/ssh/sshd_config"
  if [[ -r "$conf" ]]; then
    grep -iE "^\s*${key}\s+" "$conf" 2>/dev/null | awk '{print $2}' | head -1
  else
    echo ""
  fi
}

# ── PAM / login.defs helpers ──────────────────────────────────────────────────
login_defs_value() {
  local key="$1"
  local conf="${SYSROOT}etc/login.defs"
  if [[ -r "$conf" ]]; then
    grep -iE "^\s*${key}\s+" "$conf" 2>/dev/null | awk '{print $2}' | head -1
  else
    echo ""
  fi
}
