#!/usr/bin/env bash
# controls/registry_data.sh — CIS Debian 12 Control Registry
# Part of cisaudit — Linux CIS Hardening Auditor
#
# PURE DATA FILE — no logic here.
# One register_control() call per CIS control.
# Section 1: Initial Setup (20 controls)

# ─────────────────────────────────────────────────────────────────────────────
# 1.1 Filesystem Configuration
# ─────────────────────────────────────────────────────────────────────────────

register_control \
  --id "1.1.1.1" --section "initial_setup" --level "1" --scored "yes" \
  --title "Ensure mounting of cramfs filesystems is disabled" \
  --desc "The cramfs filesystem type is a compressed read-only Linux filesystem embedded in small footprint systems. A malicious user could use cramfs to house malicious code." \
  --fix "echo 'install cramfs /bin/false' > /etc/modprobe.d/cramfs.conf && rmmod cramfs 2>/dev/null; true"

register_control \
  --id "1.1.1.2" --section "initial_setup" --level "1" --scored "yes" \
  --title "Ensure mounting of squashfs filesystems is disabled" \
  --desc "squashfs is a compressed read-only filesystem. Disabling squashfs reduces the attack surface on the kernel." \
  --fix "echo 'install squashfs /bin/false' > /etc/modprobe.d/squashfs.conf && rmmod squashfs 2>/dev/null; true"

register_control \
  --id "1.1.1.3" --section "initial_setup" --level "2" --scored "yes" \
  --title "Ensure mounting of udf filesystems is disabled" \
  --desc "UDF is the universal disk format used to implement ISO/IEC 13346. It is the successor to the CD-ROM file system, CDFS." \
  --fix "echo 'install udf /bin/false' > /etc/modprobe.d/udf.conf && rmmod udf 2>/dev/null; true"

register_control \
  --id "1.1.2.1" --section "initial_setup" --level "1" --scored "yes" \
  --title "Ensure /tmp is a separate partition" \
  --desc "The /tmp directory is a world-writable directory used for temporary storage. Mounting /tmp on a separate partition enables the use of security options such as noexec, nodev, and nosuid." \
  --fix "Create a separate partition for /tmp in /etc/fstab or use: systemctl enable --now tmp.mount"

register_control \
  --id "1.1.2.2" --section "initial_setup" --level "1" --scored "yes" \
  --title "Ensure nodev option set on /tmp partition" \
  --desc "The nodev mount option specifies that the filesystem cannot contain special devices. Prevents users from creating block or character devices on /tmp." \
  --fix "Add 'nodev' to the /tmp entry in /etc/fstab, then run: mount -o remount,nodev /tmp"

register_control \
  --id "1.1.2.3" --section "initial_setup" --level "1" --scored "yes" \
  --title "Ensure nosuid option set on /tmp partition" \
  --desc "The nosuid mount option specifies that the filesystem cannot contain setuid files. Prevents users from executing setuid programs in /tmp." \
  --fix "Add 'nosuid' to the /tmp entry in /etc/fstab, then run: mount -o remount,nosuid /tmp"

register_control \
  --id "1.1.2.4" --section "initial_setup" --level "1" --scored "yes" \
  --title "Ensure noexec option set on /tmp partition" \
  --desc "The noexec mount option specifies that the filesystem cannot contain executable binaries. Prevents attackers from staging and executing binaries in /tmp." \
  --fix "Add 'noexec' to the /tmp entry in /etc/fstab, then run: mount -o remount,noexec /tmp"

register_control \
  --id "1.1.3.2" --section "initial_setup" --level "1" --scored "yes" \
  --title "Ensure nodev option set on /var/tmp partition" \
  --desc "The nodev mount option on /var/tmp prevents creation of device files in a world-writable directory." \
  --fix "Add 'nodev' to the /var/tmp entry in /etc/fstab, then run: mount -o remount,nodev /var/tmp"

register_control \
  --id "1.1.3.3" --section "initial_setup" --level "1" --scored "yes" \
  --title "Ensure nosuid option set on /var/tmp partition" \
  --desc "The nosuid mount option on /var/tmp prevents execution of setuid programs." \
  --fix "Add 'nosuid' to the /var/tmp entry in /etc/fstab, then run: mount -o remount,nosuid /var/tmp"

# ─────────────────────────────────────────────────────────────────────────────
# 1.2 Configure Software Updates
# ─────────────────────────────────────────────────────────────────────────────

register_control \
  --id "1.2.1" --section "initial_setup" --level "1" --scored "yes" \
  --title "Ensure package manager repositories are configured" \
  --desc "Systems need to have package manager repositories configured to ensure that patches, bug fixes, and updated software can be installed." \
  --fix "Verify /etc/apt/sources.list contains valid Debian repositories"

register_control \
  --id "1.2.2" --section "initial_setup" --level "1" --scored "yes" \
  --title "Ensure GPG keys are configured" \
  --desc "Most packages managers implement GPG key signing to verify package integrity and authenticity." \
  --fix "Run: apt-key list — verify Debian keys are present"

# ─────────────────────────────────────────────────────────────────────────────
# 1.3 Filesystem Integrity Checking
# ─────────────────────────────────────────────────────────────────────────────

register_control \
  --id "1.3.1" --section "initial_setup" --level "1" --scored "yes" \
  --title "Ensure AIDE is installed" \
  --desc "AIDE (Advanced Intrusion Detection Environment) is an intrusion detection tool used to create a cryptographic database of system files to detect filesystem changes." \
  --fix "apt install aide aide-common && aideinit"

register_control \
  --id "1.3.2" --section "initial_setup" --level "1" --scored "yes" \
  --title "Ensure filesystem integrity is regularly checked" \
  --desc "Periodic checking of the filesystem integrity is needed to detect changes to the system." \
  --fix "echo '0 5 * * * root /usr/bin/aide.wrapper --config /etc/aide/aide.conf --check' >> /etc/cron.d/aide"

# ─────────────────────────────────────────────────────────────────────────────
# 1.4 Secure Boot Settings
# ─────────────────────────────────────────────────────────────────────────────

register_control \
  --id "1.4.1" --section "initial_setup" --level "1" --scored "yes" \
  --title "Ensure bootloader password is set" \
  --desc "Setting a GRUB password prevents unauthorized users from booting the system into single-user mode and gaining root." \
  --fix "Run: grub-mkpasswd-pbkdf2 and add password_pbkdf2 root <hash> to /etc/grub.d/40_custom, then update-grub"

# ─────────────────────────────────────────────────────────────────────────────
# 1.5 Process Hardening
# ─────────────────────────────────────────────────────────────────────────────

register_control \
  --id "1.5.1" --section "initial_setup" --level "1" --scored "yes" \
  --title "Ensure address space layout randomization (ASLR) is enabled" \
  --desc "ASLR randomizes memory addresses used by processes, making memory exploitation significantly harder. kernel.randomize_va_space=2 enables full randomization." \
  --fix "echo 'kernel.randomize_va_space = 2' >> /etc/sysctl.d/60-kernel_sysctl.conf && sysctl -w kernel.randomize_va_space=2"

register_control \
  --id "1.5.2" --section "initial_setup" --level "1" --scored "yes" \
  --title "Ensure ptrace_scope is restricted" \
  --desc "ptrace allows one process to observe and control another. Restricting ptrace_scope prevents a compromised process from reading credentials from other processes (e.g., keyloggers, credential theft)." \
  --fix "echo 'kernel.yama.ptrace_scope = 1' >> /etc/sysctl.d/60-kernel_sysctl.conf && sysctl -w kernel.yama.ptrace_scope=1"

register_control \
  --id "1.5.3" --section "initial_setup" --level "1" --scored "yes" \
  --title "Ensure core dumps are restricted" \
  --desc "A core dump is the memory of an executable program that crashed. Core dumps can contain sensitive data and can be exploited. Restricting them reduces data exposure." \
  --fix "echo '* hard core 0' >> /etc/security/limits.conf && echo 'fs.suid_dumpable = 0' >> /etc/sysctl.d/60-kernel_sysctl.conf"

register_control \
  --id "1.5.4" --section "initial_setup" --level "1" --scored "yes" \
  --title "Ensure prelink is not installed" \
  --desc "prelink modifies ELF shared libraries and binaries to make them load faster. However it can interfere with AIDE and other integrity checkers, and must not be present." \
  --fix "apt purge prelink"

# ─────────────────────────────────────────────────────────────────────────────
# 1.6 Mandatory Access Control
# ─────────────────────────────────────────────────────────────────────────────

register_control \
  --id "1.6.1" --section "initial_setup" --level "1" --scored "yes" \
  --title "Ensure AppArmor is installed" \
  --desc "AppArmor is a Linux Security Module (LSM) that implements Mandatory Access Control (MAC). It restricts programs to a limited set of resources — even if compromised." \
  --fix "apt install apparmor apparmor-utils"

register_control \
  --id "1.6.2" --section "initial_setup" --level "1" --scored "yes" \
  --title "Ensure AppArmor is enabled in the bootloader configuration" \
  --desc "AppArmor must be enabled at boot time. Without the security=apparmor and apparmor=1 kernel parameters, AppArmor enforcement is disabled." \
  --fix "sed -i 's/GRUB_CMDLINE_LINUX=\"/GRUB_CMDLINE_LINUX=\"apparmor=1 security=apparmor /' /etc/default/grub && update-grub"
