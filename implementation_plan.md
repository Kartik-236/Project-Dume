# Project DUME — MVP Implementation Plan

Build a modular Linux kernel-aware host security framework across 20 files in the existing repo skeleton. All files are currently stubs (1-2 lines). The only third-party dependency is `psutil`.

---

## Proposed Changes

### Core Infrastructure

#### [MODIFY] [config.py](file:///d:/Projects/Project-Dume/Project-Dume/config.py)
Central configuration dict/module containing: DB path (`storage/events.db`), baseline path (`baseline/baseline.json`), output dir (`reporting/output`), log line limits, suspicious command/path lists, sysctl keys to monitor, severity thresholds, scoring constants.

#### [MODIFY] [event_store.py](file:///d:/Projects/Project-Dume/Project-Dume/storage/event_store.py)
SQLite-backed storage with `init_db()`, `save_events()`, `save_alert()`, `fetch_recent_alerts()`. Two tables: `events` (normalized event JSON + timestamp) and `alerts` (alert JSON + severity + timestamp). Auto-creates DB file.

---

### Baseline & Collection

#### [MODIFY] [baseline_manager.py](file:///d:/Projects/Project-Dume/Project-Dume/baseline/baseline_manager.py)
Reads `/proc/modules`, selected `/proc/sys` sysctl values, SHA256 hashes of privileged binaries. Saves/loads JSON baseline. `compare_current_to_baseline()` returns structured drift report (new/missing modules, sysctl changes, binary hash changes).

#### [MODIFY] [proc_collector.py](file:///d:/Projects/Project-Dume/Project-Dume/collectors/proc_collector.py)
Uses `psutil` to enumerate processes. Returns list of raw event dicts with pid/ppid/name/uid/euid/cmdline. Flags `euid==0` for non-system processes and suspicious command patterns.

#### [MODIFY] [dmesg_collector.py](file:///d:/Projects/Project-Dume/Project-Dume/collectors/dmesg_collector.py)
Runs `dmesg --time-format iso` via subprocess, reads tail N lines, filters for security keywords (module/insmod/modprobe/taint/audit/denied). Graceful fallback if dmesg unavailable.

#### [MODIFY] [journal_collector.py](file:///d:/Projects/Project-Dume/Project-Dume/collectors/journal_collector.py)
Runs `journalctl --no-pager -n N` via subprocess, filters for security keywords. Graceful fallback if journalctl unavailable.

#### [MODIFY] [audit_collector.py](file:///d:/Projects/Project-Dume/Project-Dume/collectors/audit_collector.py)
Reads tail of `/var/log/audit/audit.log` if present. Parses for EXECVE/SYSCALL/USER_CMD/USER_ACCT types. Extracts uid/euid and command info. Returns empty with warning if audit log missing.

#### [MODIFY] [ebpf_collector.py](file:///d:/Projects/Project-Dume/Project-Dume/collectors/ebpf_collector.py)
*New file* — documented stub only. Contains a class/function skeleton with TODO comments explaining future eBPF extension. No dependencies added.

---

### Normalization & Detection

#### [MODIFY] [normalizer.py](file:///d:/Projects/Project-Dume/Project-Dume/normalization/normalizer.py)
Converts raw events into common schema: `{timestamp, source, event_type, process_name, pid, ppid, uid, euid, target, message, risk_tags, metadata}`. Tolerant of missing fields, never crashes on malformed input.

#### [MODIFY] [rules.py](file:///d:/Projects/Project-Dume/Project-Dume/detection/rules.py)
Centralized constants: suspicious commands list, suspicious paths, severity mapping, scoring constants, configurable thresholds.

#### [MODIFY] [integrity_detector.py](file:///d:/Projects/Project-Dume/Project-Dume/detection/integrity_detector.py)
Consumes baseline comparison + normalized events. Detects: new/unknown kernel modules, suspicious module paths (/tmp, /home), sysctl drift, binary hash drift. Returns structured findings with `{finding_type, severity, score, description, evidence}`.

#### [MODIFY] [privilege_detector.py](file:///d:/Projects/Project-Dume/Project-Dume/detection/privilege_detector.py)
Consumes normalized events. Detects: abnormal euid==0, suspicious sudo/pkexec/insmod/modprobe usage, dangerous cmdline patterns. Same finding format as integrity detector.

---

### Correlation & Reporting

#### [MODIFY] [correlator.py](file:///d:/Projects/Project-Dume/Project-Dume/correlation/correlator.py)
Accepts findings from both detectors. Sums scores, applies bonus for correlated patterns (privilege + module findings together; sysctl drift + privileged command together). Outputs `{timestamp, total_score, severity, findings, summary, recommended_action}`.

#### [MODIFY] [reporter.py](file:///d:/Projects/Project-Dume/Project-Dume/reporting/reporter.py)
`print_alert_to_console()`, `save_alert_json()` (to `reporting/output/`), `generate_incident_summary()`. Auto-creates output directory.

---

### Orchestration & Packaging

#### [MODIFY] [main.py](file:///d:/Projects/Project-Dume/Project-Dume/main.py)
CLI pipeline with argparse: `--init-baseline`, `--run-once`, `--show-alerts`, `--verbose`. Default: single detection cycle. Orchestrates: init DB → load/create baseline → collect → normalize → store → detect → correlate → report.

#### [MODIFY] [requirements.txt](file:///d:/Projects/Project-Dume/Project-Dume/requirements.txt)
```
psutil
```

#### [MODIFY] [.gitignore](file:///d:/Projects/Project-Dume/Project-Dume/.gitignore)
Add: `reporting/output/`, `baseline/baseline.json`, `*.sqlite3`, `*.db`, `*.log`, `env/`.

#### [NEW] [Dockerfile](file:///d:/Projects/Project-Dume/Project-Dume/Dockerfile)
Based on `python:3.11-slim`. Installs `procps`, `kmod`, `util-linux`. Copies project, installs deps. Default CMD: `python main.py --run-once --verbose`.

#### [NEW] [docker-compose.yml](file:///d:/Projects/Project-Dume/Project-Dume/docker-compose.yml)
Simple service definition with optional privileged mode and `/proc`/`/var/log` bind mounts commented out.

---

### Documentation

#### [MODIFY] [README.md](file:///d:/Projects/Project-Dume/Project-Dume/README.md)
Project title, description, architecture flow, repo structure, local run instructions, Docker instructions, limitations, MVP scope, future scope.

#### [MODIFY] [synopsis.md](file:///d:/Projects/Project-Dume/Project-Dume/docs/synopsis.md)
Brief seminar synopsis.

#### [MODIFY] [architecture.md](file:///d:/Projects/Project-Dume/Project-Dume/docs/architecture.md)
Module overview with data flow diagram.

---

## Verification Plan

### Automated Checks

1. **Syntax validation** — run `py -m py_compile <file>` on every [.py](file:///d:/Projects/Project-Dume/Project-Dume/main.py) file to confirm no syntax errors:
   ```
   cd d:\Projects\Project-Dume\Project-Dume
   python -m py_compile config.py
   python -m py_compile main.py
   python -m py_compile storage/event_store.py
   ... (all .py files)
   ```

2. **Import check** — run `python -c "import config; import storage.event_store; ..."` to confirm import graph works.

3. **CLI help** — run `python main.py --help` to verify argparse is wired correctly.

4. **Docker build** — run `docker build -t project-dume .` to verify Dockerfile is valid.

### Manual Verification (on Linux/Docker)

> [!IMPORTANT]
> Full functional testing requires a Linux environment. These steps can be run inside the Docker container or on a Kali/Ubuntu VM.

1. Clone repo on a Linux machine (or use Docker)
2. Run `python main.py --init-baseline --verbose` — should create `baseline/baseline.json`
3. Run `python main.py --run-once --verbose` — should complete a detection cycle and print results
4. Run `python main.py --show-alerts` — should show any stored alerts
5. Run `docker build -t project-dume . && docker run --rm project-dume` — should execute a detection cycle inside container

> [!NOTE]
> Since development is on Windows, syntax/import checks can be run there, but functional testing of Linux telemetry collectors needs Linux or Docker.
