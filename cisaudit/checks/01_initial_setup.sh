#!/usr/bin/env bash
# checks/01_initial_setup.sh — CIS Section 1: Initial Setup check functions
# Part of cisaudit — Linux CIS Hardening Auditor
#
# Each function is named check_<id_with_underscores>()
# Convention: "1.1.1.1" → check_1_1_1_1
# All filesystem access goes through utils.sh helpers (SYSROOT-aware).

# ─────────────────────────────────────────────────────────────────────────────
# SHARED HELPERS (private to this file — prefix with _)
# ─────────────────────────────────────────────────────────────────────────────

# _check_module_disabled <control_id> <module_name>
# Checks that a kernel module is blocked in modprobe.d
_check_module_disabled() {
  local id="$1"
  local mod="$2"

  # Check 1: blocked in modprobe.d
  if module_is_blocked "$mod"; then
    # Check 2: not currently loaded (only on live system)
    if [[ "$SYSROOT" == "/" ]]; then
      if module_is_loaded "$mod"; then
        record_result "$id" "$STATUS_WARN" \
          "Module '$mod' is in modprobe.d blocklist but is currently loaded. Reboot required."
        return
      fi
    fi
    record_result "$id" "$STATUS_PASS" \
      "Module '$mod' is blocked in /etc/modprobe.d — cannot be loaded."
  else
    local evidence="No 'install $mod /bin/false' found in ${SYSROOT}etc/modprobe.d/"
    record_result "$id" "$STATUS_FAIL" "$evidence"
  fi
}

# _check_mount_option <control_id> <mountpoint> <option>
_check_mount_option() {
  local id="$1"
  local mountpoint="$2"
  local option="$3"

  if mount_option_set "$mountpoint" "$option"; then
    record_result "$id" "$STATUS_PASS" \
      "$option is set on $mountpoint in ${SYSROOT}etc/fstab"
  else
    record_result "$id" "$STATUS_FAIL" \
      "$option is NOT set on $mountpoint in ${SYSROOT}etc/fstab"
  fi
}

# _check_sysctl_value <control_id> <param> <expected_value>
_check_sysctl_value() {
  local id="$1"
  local param="$2"
  local expected="$3"

  local actual
  actual="$(get_sysctl "$param")"
  actual="${actual//[[:space:]]/}"   # strip whitespace

  if [[ -z "$actual" ]]; then
    record_result "$id" "$STATUS_SKIP" \
      "Cannot read kernel parameter '$param' in test mode (no proc/sys file found)"
  elif [[ "$actual" == "$expected" ]]; then
    record_result "$id" "$STATUS_PASS" \
      "kernel.$param = $actual (expected $expected)"
  else
    record_result "$id" "$STATUS_FAIL" \
      "kernel.$param = '$actual' (expected '$expected')"
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
# 1.1.1 — Filesystem module controls
# ─────────────────────────────────────────────────────────────────────────────

check_1_1_1_1() { _check_module_disabled "1.1.1.1" "cramfs";   }
check_1_1_1_2() { _check_module_disabled "1.1.1.2" "squashfs"; }
check_1_1_1_3() { _check_module_disabled "1.1.1.3" "udf";      }

# ─────────────────────────────────────────────────────────────────────────────
# 1.1.2 — /tmp mount options
# ─────────────────────────────────────────────────────────────────────────────

check_1_1_2_1() {
  local id="1.1.2.1"
  local fstab="${SYSROOT}etc/fstab"

  # Check if /tmp is a separate entry in fstab or if tmp.mount exists
  local tmpfs_unit="${SYSROOT}etc/systemd/system/tmp.mount"
  local fstab_has_tmp=0
  if [[ -r "$fstab" ]] && grep -qE '^\S+\s+/tmp\s+' "$fstab"; then
    fstab_has_tmp=1
  fi
  local unit_exists=0
  [[ -f "$tmpfs_unit" ]] && unit_exists=1

  if (( fstab_has_tmp || unit_exists )); then
    record_result "$id" "$STATUS_PASS" \
      "/tmp is mounted as a separate partition (found in fstab or tmp.mount unit)"
  else
    record_result "$id" "$STATUS_FAIL" \
      "/tmp does not appear to be a separate partition in ${SYSROOT}etc/fstab"
  fi
}

check_1_1_2_2() { _check_mount_option "1.1.2.2" "/tmp" "nodev";  }
check_1_1_2_3() { _check_mount_option "1.1.2.3" "/tmp" "nosuid"; }
check_1_1_2_4() { _check_mount_option "1.1.2.4" "/tmp" "noexec"; }

# ─────────────────────────────────────────────────────────────────────────────
# 1.1.3 — /var/tmp mount options
# ─────────────────────────────────────────────────────────────────────────────

check_1_1_3_2() { _check_mount_option "1.1.3.2" "/var/tmp" "nodev";  }
check_1_1_3_3() { _check_mount_option "1.1.3.3" "/var/tmp" "nosuid"; }

# ─────────────────────────────────────────────────────────────────────────────
# 1.2 — Package manager / GPG
# ─────────────────────────────────────────────────────────────────────────────

check_1_2_1() {
  local id="1.2.1"
  local sources="${SYSROOT}etc/apt/sources.list"
  local sources_dir="${SYSROOT}etc/apt/sources.list.d"

  local has_repo=0
  if [[ -r "$sources" ]] && grep -qE '^deb\s' "$sources"; then
    has_repo=1
  fi
  if [[ -d "$sources_dir" ]] && grep -rqE '^deb\s' "$sources_dir" 2>/dev/null; then
    has_repo=1
  fi

  if (( has_repo )); then
    local repo_count
    repo_count=$(grep -rE '^deb\s' "$sources" "$sources_dir"/ 2>/dev/null | wc -l || echo 0)
    record_result "$id" "$STATUS_PASS" \
      "Found $repo_count active repository entries in apt sources"
  else
    record_result "$id" "$STATUS_FAIL" \
      "No valid 'deb' entries found in ${SYSROOT}etc/apt/sources.list or sources.list.d/"
  fi
}

check_1_2_2() {
  local id="1.2.2"
  # Check for Debian keyring or trusted keys
  local keyring="${SYSROOT}etc/apt/trusted.gpg"
  local keyring_dir="${SYSROOT}etc/apt/trusted.gpg.d"
  local keyrings_dir="${SYSROOT}usr/share/keyrings"

  if [[ -f "$keyring" ]] || \
     ( [[ -d "$keyring_dir" ]] && ls "$keyring_dir"/*.gpg 2>/dev/null | grep -q . ) || \
     ( [[ -d "$keyrings_dir" ]] && ls "$keyrings_dir"/*.gpg 2>/dev/null | grep -q . ); then
    record_result "$id" "$STATUS_PASS" \
      "APT GPG keys found in trusted keyring locations"
  else
    record_result "$id" "$STATUS_FAIL" \
      "No GPG keyring files found in ${SYSROOT}etc/apt/trusted.gpg.d/ or usr/share/keyrings/"
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
# 1.3 — Filesystem Integrity (AIDE)
# ─────────────────────────────────────────────────────────────────────────────

check_1_3_1() {
  local id="1.3.1"
  if package_is_installed "aide"; then
    record_result "$id" "$STATUS_PASS" "AIDE package is installed"
  else
    record_result "$id" "$STATUS_FAIL" "AIDE is not installed — install with: apt install aide aide-common"
  fi
}

check_1_3_2() {
  local id="1.3.2"
  # Check for AIDE in cron or a systemd timer
  local cron_daily="${SYSROOT}etc/cron.daily"
  local cron_d="${SYSROOT}etc/cron.d"
  local aide_timer="${SYSROOT}etc/systemd/system/aidecheck.timer"

  local found_cron=0
  if [[ -d "$cron_daily" ]] && ls "$cron_daily"/aide* 2>/dev/null | grep -q .; then
    found_cron=1
  fi
  if [[ -d "$cron_d" ]] && grep -rl "aide" "$cron_d" 2>/dev/null | grep -q .; then
    found_cron=1
  fi
  if [[ -f "$aide_timer" ]]; then
    found_cron=1
  fi

  if (( found_cron )); then
    record_result "$id" "$STATUS_PASS" \
      "AIDE periodic check found in cron or systemd timer"
  else
    record_result "$id" "$STATUS_FAIL" \
      "No AIDE cron job or systemd timer found — filesystem integrity not regularly checked"
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
# 1.4 — Secure Boot (GRUB password)
# ─────────────────────────────────────────────────────────────────────────────

check_1_4_1() {
  local id="1.4.1"
  local grub_dir="${SYSROOT}etc/grub.d"
  local grub_cfg="${SYSROOT}boot/grub/grub.cfg"

  local has_password=0
  # Look for pbkdf2 hash in grub config files
  if [[ -d "$grub_dir" ]] && grep -rl "password_pbkdf2" "$grub_dir" 2>/dev/null | grep -q .; then
    has_password=1
  fi
  if [[ -r "$grub_cfg" ]] && grep -q "password_pbkdf2" "$grub_cfg"; then
    has_password=1
  fi

  if (( has_password )); then
    record_result "$id" "$STATUS_PASS" \
      "GRUB bootloader password (pbkdf2 hash) is configured"
  else
    record_result "$id" "$STATUS_FAIL" \
      "No GRUB bootloader password found in ${SYSROOT}etc/grub.d/ or boot/grub/grub.cfg"
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
# 1.5 — Process Hardening
# ─────────────────────────────────────────────────────────────────────────────

check_1_5_1() {
  _check_sysctl_value "1.5.1" "kernel.randomize_va_space" "2"
}

check_1_5_2() {
  _check_sysctl_value "1.5.2" "kernel.yama.ptrace_scope" "1"
}

check_1_5_3() {
  local id="1.5.3"
  # Check fs.suid_dumpable = 0 (core dump restriction)
  local sysctl_val
  sysctl_val="$(get_sysctl "fs.suid_dumpable")"
  sysctl_val="${sysctl_val//[[:space:]]/}"

  local limits="${SYSROOT}etc/security/limits.conf"
  local limits_dir="${SYSROOT}etc/security/limits.d"
  local has_limit=0

  if [[ -r "$limits" ]] && grep -qE '^\*\s+hard\s+core\s+0' "$limits"; then
    has_limit=1
  fi
  if [[ -d "$limits_dir" ]] && grep -rqE '^\*\s+hard\s+core\s+0' "$limits_dir" 2>/dev/null; then
    has_limit=1
  fi

  if [[ -z "$sysctl_val" && ! -r "$limits" ]]; then
    record_result "$id" "$STATUS_SKIP" "Cannot evaluate core dump settings in test mode"
    return
  fi

  if [[ "$sysctl_val" == "0" ]] && (( has_limit )); then
    record_result "$id" "$STATUS_PASS" \
      "fs.suid_dumpable=0 and '* hard core 0' found in limits.conf"
  elif [[ "$sysctl_val" == "0" ]]; then
    record_result "$id" "$STATUS_WARN" \
      "fs.suid_dumpable=0 but '* hard core 0' not found in limits.conf"
  elif (( has_limit )); then
    record_result "$id" "$STATUS_WARN" \
      "'* hard core 0' found in limits.conf but fs.suid_dumpable is '$sysctl_val' (expected 0)"
  else
    record_result "$id" "$STATUS_FAIL" \
      "Core dumps not restricted: fs.suid_dumpable='${sysctl_val:-not set}', no limits.conf entry"
  fi
}

check_1_5_4() {
  local id="1.5.4"
  if package_is_installed "prelink"; then
    record_result "$id" "$STATUS_FAIL" \
      "prelink is installed — remove with: apt purge prelink"
  else
    record_result "$id" "$STATUS_PASS" \
      "prelink is not installed (good — it interferes with integrity checkers)"
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
# 1.6 — Mandatory Access Control (AppArmor)
# ─────────────────────────────────────────────────────────────────────────────

check_1_6_1() {
  local id="1.6.1"
  if package_is_installed "apparmor"; then
    record_result "$id" "$STATUS_PASS" "AppArmor package is installed"
  else
    record_result "$id" "$STATUS_FAIL" \
      "AppArmor is not installed — install with: apt install apparmor apparmor-utils"
  fi
}

check_1_6_2() {
  local id="1.6.2"
  local grub_default="${SYSROOT}etc/default/grub"
  local grub_cfg="${SYSROOT}boot/grub/grub.cfg"

  local has_apparmor_param=0
  if [[ -r "$grub_default" ]] && \
     grep -qE 'GRUB_CMDLINE_LINUX.*apparmor=1' "$grub_default" && \
     grep -qE 'GRUB_CMDLINE_LINUX.*security=apparmor' "$grub_default"; then
    has_apparmor_param=1
  fi
  if [[ -r "$grub_cfg" ]] && \
     grep -qE 'apparmor=1' "$grub_cfg" && \
     grep -qE 'security=apparmor' "$grub_cfg"; then
    has_apparmor_param=1
  fi

  if (( has_apparmor_param )); then
    record_result "$id" "$STATUS_PASS" \
      "AppArmor kernel parameters (apparmor=1 security=apparmor) found in GRUB configuration"
  else
    record_result "$id" "$STATUS_FAIL" \
      "AppArmor kernel parameters not found in ${SYSROOT}etc/default/grub or boot/grub/grub.cfg"
  fi
}
