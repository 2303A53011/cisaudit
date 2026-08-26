#!/usr/bin/env bash
# tests/test_01_initial_setup.sh — Tests for CIS Section 1: Initial Setup
# Part of cisaudit — Linux CIS Hardening Auditor
#
# Each test_case_* function tests one control against both the PASS and FAIL fixtures.
# Uses assert_status and assert_evidence_contains from test_helpers.sh.

FIXTURES_PASS="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/testdata/fixtures"
FIXTURES_FAIL="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/testdata/fixtures_fail"

# ─────────────────────────────────────────────────────────────────────────────
# 1.1.1.1 — cramfs disabled
# ─────────────────────────────────────────────────────────────────────────────
test_case_1_1_1_1_pass() {
  setup_test "$FIXTURES_PASS"
  run_single_check "1.1.1.1"
  assert_status "1.1.1.1" "PASS" "cramfs should be PASS with proper modprobe.d config"
  assert_evidence_contains "1.1.1.1" "blocked" "Evidence should mention 'blocked'"
}

test_case_1_1_1_1_fail() {
  setup_test "$FIXTURES_FAIL"
  run_single_check "1.1.1.1"
  assert_status "1.1.1.1" "FAIL" "cramfs should be FAIL when not in modprobe.d"
}

# ─────────────────────────────────────────────────────────────────────────────
# 1.1.1.2 — squashfs disabled
# ─────────────────────────────────────────────────────────────────────────────
test_case_1_1_1_2_pass() {
  setup_test "$FIXTURES_PASS"
  run_single_check "1.1.1.2"
  assert_status "1.1.1.2" "PASS" "squashfs should be PASS with proper modprobe.d config"
}

test_case_1_1_1_2_fail() {
  setup_test "$FIXTURES_FAIL"
  run_single_check "1.1.1.2"
  assert_status "1.1.1.2" "FAIL" "squashfs should be FAIL when not blocked"
}

# ─────────────────────────────────────────────────────────────────────────────
# 1.1.1.3 — udf disabled
# ─────────────────────────────────────────────────────────────────────────────
test_case_1_1_1_3_pass() {
  setup_test "$FIXTURES_PASS"
  run_single_check "1.1.1.3"
  assert_status "1.1.1.3" "PASS" "udf should be PASS with proper modprobe.d config"
}

test_case_1_1_1_3_fail() {
  setup_test "$FIXTURES_FAIL"
  run_single_check "1.1.1.3"
  assert_status "1.1.1.3" "FAIL" "udf should be FAIL when not blocked"
}

# ─────────────────────────────────────────────────────────────────────────────
# 1.1.2.1 — /tmp separate partition
# ─────────────────────────────────────────────────────────────────────────────
test_case_1_1_2_1_pass() {
  setup_test "$FIXTURES_PASS"
  run_single_check "1.1.2.1"
  assert_status "1.1.2.1" "PASS" "/tmp should be PASS when in fstab as separate partition"
}

test_case_1_1_2_1_fail() {
  setup_test "$FIXTURES_FAIL"
  run_single_check "1.1.2.1"
  assert_status "1.1.2.1" "FAIL" "/tmp should be FAIL when not a separate partition"
}

# ─────────────────────────────────────────────────────────────────────────────
# 1.1.2.2 — nodev on /tmp
# ─────────────────────────────────────────────────────────────────────────────
test_case_1_1_2_2_pass() {
  setup_test "$FIXTURES_PASS"
  run_single_check "1.1.2.2"
  assert_status "1.1.2.2" "PASS" "nodev on /tmp should PASS"
}

test_case_1_1_2_2_fail() {
  setup_test "$FIXTURES_FAIL"
  run_single_check "1.1.2.2"
  assert_status "1.1.2.2" "FAIL" "nodev on /tmp should FAIL when not set"
}

# ─────────────────────────────────────────────────────────────────────────────
# 1.1.2.3 — nosuid on /tmp
# ─────────────────────────────────────────────────────────────────────────────
test_case_1_1_2_3_pass() {
  setup_test "$FIXTURES_PASS"
  run_single_check "1.1.2.3"
  assert_status "1.1.2.3" "PASS" "nosuid on /tmp should PASS"
}

test_case_1_1_2_3_fail() {
  setup_test "$FIXTURES_FAIL"
  run_single_check "1.1.2.3"
  assert_status "1.1.2.3" "FAIL" "nosuid on /tmp should FAIL when not set"
}

# ─────────────────────────────────────────────────────────────────────────────
# 1.1.2.4 — noexec on /tmp
# ─────────────────────────────────────────────────────────────────────────────
test_case_1_1_2_4_pass() {
  setup_test "$FIXTURES_PASS"
  run_single_check "1.1.2.4"
  assert_status "1.1.2.4" "PASS" "noexec on /tmp should PASS"
}

test_case_1_1_2_4_fail() {
  setup_test "$FIXTURES_FAIL"
  run_single_check "1.1.2.4"
  assert_status "1.1.2.4" "FAIL" "noexec on /tmp should FAIL when not set"
}

# ─────────────────────────────────────────────────────────────────────────────
# 1.2.1 — Package repositories configured
# ─────────────────────────────────────────────────────────────────────────────
test_case_1_2_1_pass() {
  setup_test "$FIXTURES_PASS"
  run_single_check "1.2.1"
  assert_status "1.2.1" "PASS" "Repository check should PASS when sources.list has deb entries"
}

# ─────────────────────────────────────────────────────────────────────────────
# 1.3.1 — AIDE installed
# ─────────────────────────────────────────────────────────────────────────────
test_case_1_3_1_pass() {
  setup_test "$FIXTURES_PASS"
  run_single_check "1.3.1"
  assert_status "1.3.1" "PASS" "AIDE should PASS when dpkg sentinel file exists"
}

test_case_1_3_1_fail() {
  setup_test "$FIXTURES_FAIL"
  run_single_check "1.3.1"
  assert_status "1.3.1" "FAIL" "AIDE should FAIL when not installed"
}

# ─────────────────────────────────────────────────────────────────────────────
# 1.4.1 — GRUB bootloader password
# ─────────────────────────────────────────────────────────────────────────────
test_case_1_4_1_pass() {
  setup_test "$FIXTURES_PASS"
  run_single_check "1.4.1"
  assert_status "1.4.1" "PASS" "GRUB password should PASS when pbkdf2 hash in grub.d"
  assert_evidence_contains "1.4.1" "pbkdf2" "Evidence should mention pbkdf2"
}

test_case_1_4_1_fail() {
  setup_test "$FIXTURES_FAIL"
  run_single_check "1.4.1"
  assert_status "1.4.1" "FAIL" "GRUB password should FAIL when not configured"
}

# ─────────────────────────────────────────────────────────────────────────────
# 1.5.1 — ASLR enabled (kernel.randomize_va_space = 2)
# ─────────────────────────────────────────────────────────────────────────────
test_case_1_5_1_pass() {
  setup_test "$FIXTURES_PASS"
  run_single_check "1.5.1"
  assert_status "1.5.1" "PASS" "ASLR should PASS when randomize_va_space=2"
}

test_case_1_5_1_skip() {
  # In fail fixture, proc/sys files don't exist → SKIP
  setup_test "$FIXTURES_FAIL"
  run_single_check "1.5.1"
  assert_status "1.5.1" "SKIP" "ASLR should SKIP when proc/sys file is missing in test mode"
}

# ─────────────────────────────────────────────────────────────────────────────
# 1.5.2 — ptrace_scope restricted
# ─────────────────────────────────────────────────────────────────────────────
test_case_1_5_2_pass() {
  setup_test "$FIXTURES_PASS"
  run_single_check "1.5.2"
  assert_status "1.5.2" "PASS" "ptrace_scope should PASS when set to 1"
}

# ─────────────────────────────────────────────────────────────────────────────
# 1.5.4 — prelink not installed
# ─────────────────────────────────────────────────────────────────────────────
test_case_1_5_4_pass() {
  setup_test "$FIXTURES_PASS"
  run_single_check "1.5.4"
  assert_status "1.5.4" "PASS" "prelink should PASS when not installed"
}

# ─────────────────────────────────────────────────────────────────────────────
# 1.6.1 — AppArmor installed
# ─────────────────────────────────────────────────────────────────────────────
test_case_1_6_1_pass() {
  setup_test "$FIXTURES_PASS"
  run_single_check "1.6.1"
  assert_status "1.6.1" "PASS" "AppArmor should PASS when dpkg sentinel exists"
}

test_case_1_6_1_fail() {
  setup_test "$FIXTURES_FAIL"
  run_single_check "1.6.1"
  assert_status "1.6.1" "FAIL" "AppArmor should FAIL when not installed"
}

# ─────────────────────────────────────────────────────────────────────────────
# 1.6.2 — AppArmor in GRUB
# ─────────────────────────────────────────────────────────────────────────────
test_case_1_6_2_pass() {
  setup_test "$FIXTURES_PASS"
  run_single_check "1.6.2"
  assert_status "1.6.2" "PASS" "AppArmor GRUB params should PASS in fixtures"
}

test_case_1_6_2_fail() {
  setup_test "$FIXTURES_FAIL"
  run_single_check "1.6.2"
  assert_status "1.6.2" "FAIL" "AppArmor GRUB params should FAIL when not in grub config"
}
