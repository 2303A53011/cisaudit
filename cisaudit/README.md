# 🔒 cisaudit — Linux CIS Hardening Auditor

A **standalone, dependency-free Bash CLI tool** that audits a Linux host against the
[CIS Debian Linux 12 Benchmark v1.1.0](https://www.cisecurity.org/benchmark/debian_linux),
producing a scored compliance report in terminal, JSON, or HTML format.

> **Zero external dependencies** — Bash 4+ only. No Python, no `jq`, no network calls.  
> Designed for security auditing, compliance evidence, and offline/forensic use.

---

## ✨ Features

| Feature | Details |
|---|---|
| 🔐 **20 CIS Controls** | CIS Section 1 (Initial Setup) — most interview-critical controls |
| 📊 **3 Report Formats** | Terminal (colored), JSON (machine-readable), HTML (dark-themed, shareable) |
| 🧪 **Test Mode** | Run against a mock filesystem — no root, no live system required |
| 📋 **Baseline & Diff** | Save runs as baselines; compare across runs to detect regressions |
| 🚪 **CI Exit Codes** | Exits 1 if score < 80% — use as a pre-deployment gate |
| 📁 **Fixture Trees** | Pass/fail test fixtures for every control |

---

## 🚀 Quick Start

### 1. Clone / Copy to your Debian/Ubuntu system

```bash
git clone https://github.com/yourusername/cisaudit.git
cd cisaudit
```

### 2. Install (adds `cisaudit` to your PATH)

```bash
sudo bash install.sh
```

### 3. Run in test mode first (no root needed)

```bash
# Mostly-PASS run
cisaudit -t testdata/fixtures

# Mostly-FAIL run (shows what a misconfigured system looks like)
cisaudit -t testdata/fixtures_fail
```

### 4. Audit your real system

```bash
sudo cisaudit
```

### 5. Generate reports

```bash
# HTML report — open in browser
sudo cisaudit -f html -o report.html
xdg-open report.html

# JSON report — machine-readable / SIEM ingestion
sudo cisaudit -f json -o report.json
python3 -m json.tool report.json   # validate + pretty-print

# Show only failures
sudo cisaudit --failures-only
```

### 6. Run the test suite

```bash
bash tests/test_runner.sh
```

---

## 📋 CLI Reference

```
cisaudit [OPTIONS]

OPTIONS:
  -t, --test <dir>         Run in test mode against a mock filesystem
  -f, --format <fmt>       Output format: terminal (default), json, html
  -o, --output <file>      Write output to file instead of stdout
  -l, --level <1|2>        Restrict to CIS Level 1 or Level 2 controls
  --baseline <file>        Save this run as a named baseline (JSON)
  --diff <file>            Compare this run against a saved baseline
  --summary                Print summary scores only
  --failures-only          Show only FAIL/WARN controls
  --no-color               Disable ANSI colors (also: NO_COLOR=1)
  --version                Print version
  -h, --help               Print help
```

---

## 📁 Project Structure

```
cisaudit/
├── cisaudit.sh               # Entry point: CLI parsing + orchestration
├── install.sh                # One-command installer
├── lib/
│   ├── constants.sh          # ANSI colors, status constants, section names
│   ├── utils.sh              # SYSROOT-aware primitives (file_exists, get_sysctl, ...)
│   ├── registry.sh           # register_control(), record_result()
│   ├── engine.sh             # compute_scores() with awk float math
│   ├── report_terminal.sh    # Colored terminal report with progress bars
│   ├── report_json.sh        # Hand-rolled JSON (no jq)
│   ├── report_html.sh        # Dark-themed standalone HTML report
│   └── baseline.sh           # Baseline save + drift detection
├── controls/
│   └── registry_data.sh      # 20 register_control() calls — pure data
├── checks/
│   └── 01_initial_setup.sh   # 20 check functions (Section 1)
├── testdata/
│   ├── fixtures/             # Mock filesystem that PASSES controls
│   └── fixtures_fail/        # Mock filesystem that FAILS controls
└── tests/
    ├── test_runner.sh        # Test discovery + subshell isolation
    ├── test_helpers.sh       # assert_status, assert_evidence_contains
    └── test_01_initial_setup.sh  # Tests for all 20 Section 1 controls
```

---

## 🔑 Key Design Decisions (for interviews)

### 1. The SYSROOT Abstraction
Every file operation goes through `${SYSROOT}/path` instead of an absolute path.  
`SYSROOT="/"` → live system. `SYSROOT="testdata/fixtures/"` → test mode.  
**This one variable makes 100% of checks testable without root and without a real server.**

### 2. Registry Pattern (Data, not Dispatch)
Controls are stored as data in associative arrays, not as a giant `if`/`case` chain.  
The check function name is **derived** from the control ID:  
`"1.1.1.1"` → `check_1_1_1_1()` — no lookup table needed.

### 3. Shared Helper Pattern
Repeated check shapes (e.g., "is module X blocked?") are in a single `_check_module_disabled` helper.  
Each `check_*` function is a **one-line wrapper** supplying only the different parameters.  
Bug fix in one helper = all 3 module checks fixed simultaneously.

### 4. Zero External Dependencies
JSON is hand-serialized (`json_escape`) instead of shelling out to `jq`.  
Float math uses `awk` (the one POSIX tool with floating point).  
**Runs on a minimal Debian install, an air-gapped forensic image, or a CI container.**

### 5. Adding a New Control
Touch exactly **two files**:
1. `controls/registry_data.sh` — add one `register_control()` call
2. `checks/01_initial_setup.sh` — add one `check_X_X_X()` function

The engine, all reporters, and the baseline module never need to change.

---

## 🛡️ CIS Controls Implemented

| ID | Title | Level |
|---|---|---|
| 1.1.1.1 | Ensure mounting of cramfs filesystems is disabled | 1 |
| 1.1.1.2 | Ensure mounting of squashfs filesystems is disabled | 1 |
| 1.1.1.3 | Ensure mounting of udf filesystems is disabled | 2 |
| 1.1.2.1 | Ensure /tmp is a separate partition | 1 |
| 1.1.2.2 | Ensure nodev option set on /tmp partition | 1 |
| 1.1.2.3 | Ensure nosuid option set on /tmp partition | 1 |
| 1.1.2.4 | Ensure noexec option set on /tmp partition | 1 |
| 1.1.3.2 | Ensure nodev option set on /var/tmp partition | 1 |
| 1.1.3.3 | Ensure nosuid option set on /var/tmp partition | 1 |
| 1.2.1 | Ensure package manager repositories are configured | 1 |
| 1.2.2 | Ensure GPG keys are configured | 1 |
| 1.3.1 | Ensure AIDE is installed | 1 |
| 1.3.2 | Ensure filesystem integrity is regularly checked | 1 |
| 1.4.1 | Ensure bootloader password is set | 1 |
| 1.5.1 | Ensure ASLR is enabled (randomize_va_space=2) | 1 |
| 1.5.2 | Ensure ptrace_scope is restricted | 1 |
| 1.5.3 | Ensure core dumps are restricted | 1 |
| 1.5.4 | Ensure prelink is not installed | 1 |
| 1.6.1 | Ensure AppArmor is installed | 1 |
| 1.6.2 | Ensure AppArmor is enabled in bootloader config | 1 |

---

## 🎓 Interview Prep

**Q: What is the CIS Benchmark?**  
A: Center for Internet Security — industry-standard hardening guidelines used by enterprises for SOC 2, PCI DSS, and HIPAA compliance. Level 1 = server-safe defaults. Level 2 = more aggressive hardening.

**Q: How does test mode work?**  
A: Every filesystem check goes through `${SYSROOT}/path`. In test mode I point SYSROOT at `testdata/fixtures/` — a fake directory tree that mimics `/etc`, `/proc/sys`, etc. No root, no real system needed.

**Q: What is ASLR and why does control 1.5.1 matter?**  
A: Address Space Layout Randomization — the kernel randomizes where code, stack, and heap are loaded in memory, making buffer overflow exploits unreliable. `kernel.randomize_va_space=2` enables full randomization.

**Q: What is AppArmor?**  
A: A Linux Security Module implementing Mandatory Access Control (MAC). Even if a process is compromised, AppArmor's policy limits what files/network it can access. It's different from DAC (standard Unix permissions) because it's enforced by the kernel, not the process owner.

**Q: Why no `jq` dependency?**  
A: Designed for forensic/offline use — must run on a minimal Debian install, an air-gapped system, or inside a CI container with no package installation step. I hand-serialize JSON in Bash using string substitution.

**Q: How would you add a new control?**  
A: Two files: (1) one `register_control()` call in `controls/registry_data.sh`, (2) one `check_X_X_X()` function in the relevant checks file. Nothing in the engine, reporters, or entry point changes — that's the registry pattern payoff.

---

## ⚠️ Security Note

> Passing all CIS controls does **not** mean your system is unbreakable.  
> CIS hardening reduces attack surface and blast radius — defense-in-depth, patching, and monitoring are still essential.

---

## 📄 License

MIT — free to use, fork, and extend.
