# Project DUME MVP — Walkthrough

## What Was Built

A complete modular MVP of a Linux kernel-aware host security framework, implemented across **22 files** in the existing repo skeleton.

### Files Created / Modified

| Category | Files |
|---|---|
| **Core** | [config.py](file:///d:/Projects/Project-Dume/Project-Dume/config.py), [main.py](file:///d:/Projects/Project-Dume/Project-Dume/main.py), [requirements.txt](file:///d:/Projects/Project-Dume/Project-Dume/requirements.txt), [.gitignore](file:///d:/Projects/Project-Dume/Project-Dume/.gitignore) |
| **Packaging** | [Dockerfile](file:///d:/Projects/Project-Dume/Project-Dume/Dockerfile), [docker-compose.yml](file:///d:/Projects/Project-Dume/Project-Dume/docker-compose.yml) |
| **Package Inits** | 7× [__init__.py](file:///d:/Projects/Project-Dume/Project-Dume/storage/__init__.py) (baseline, collectors, normalization, detection, correlation, reporting, storage) |
| **Baseline** | [baseline/baseline_manager.py](file:///d:/Projects/Project-Dume/Project-Dume/baseline/baseline_manager.py) |
| **Collectors** | [proc_collector.py](file:///d:/Projects/Project-Dume/Project-Dume/collectors/proc_collector.py), [dmesg_collector.py](file:///d:/Projects/Project-Dume/Project-Dume/collectors/dmesg_collector.py), [journal_collector.py](file:///d:/Projects/Project-Dume/Project-Dume/collectors/journal_collector.py), [audit_collector.py](file:///d:/Projects/Project-Dume/Project-Dume/collectors/audit_collector.py), [ebpf_collector.py](file:///d:/Projects/Project-Dume/Project-Dume/collectors/ebpf_collector.py) (stub) |
| **Normalization** | [normalization/normalizer.py](file:///d:/Projects/Project-Dume/Project-Dume/normalization/normalizer.py) |
| **Detection** | [detection/rules.py](file:///d:/Projects/Project-Dume/Project-Dume/detection/rules.py), [integrity_detector.py](file:///d:/Projects/Project-Dume/Project-Dume/detection/integrity_detector.py), [privilege_detector.py](file:///d:/Projects/Project-Dume/Project-Dume/detection/privilege_detector.py) |
| **Correlation** | [correlation/correlator.py](file:///d:/Projects/Project-Dume/Project-Dume/correlation/correlator.py) |
| **Reporting** | [reporting/reporter.py](file:///d:/Projects/Project-Dume/Project-Dume/reporting/reporter.py) |
| **Storage** | [storage/event_store.py](file:///d:/Projects/Project-Dume/Project-Dume/storage/event_store.py) |
| **Docs** | [README.md](file:///d:/Projects/Project-Dume/Project-Dume/README.md), [docs/synopsis.md](file:///d:/Projects/Project-Dume/Project-Dume/docs/synopsis.md), [docs/architecture.md](file:///d:/Projects/Project-Dume/Project-Dume/docs/architecture.md) |

## Verification Results (Windows)

| Check | Result |
|---|---|
| `py_compile` on all 15 .py files | ✅ All pass |
| `python main.py --help` | ✅ CLI renders correctly |
| `python main.py --show-alerts` | ✅ Returns "No alerts stored yet" |
| `python main.py --run-once` | ✅ Exit code 0, completes full pipeline |

## Assumptions Made

1. **Single dependency**: Only `psutil` is needed — all other logic uses Python stdlib
2. **Graceful degradation**: All Linux-specific collectors (dmesg, journalctl, audit, /proc/modules) return empty lists on Windows or when access is denied
3. **Auto-baseline**: If no baseline exists during `--run-once`, one is created automatically with a guidance message
4. **Docker non-privileged by default**: [docker-compose.yml](file:///d:/Projects/Project-Dume/Project-Dume/docker-compose.yml) has privileged mode and volume mounts commented out
5. **eBPF is stub-only**: No eBPF libraries — just a documented placeholder

## Commands to Run

### On Windows (syntax/import validation)

```powershell
cd d:\Projects\Project-Dume\Project-Dume

# Install deps
pip install -r requirements.txt

# Syntax check all files
python -m py_compile config.py
python -m py_compile main.py
python -m py_compile storage\event_store.py
python -m py_compile baseline\baseline_manager.py
python -m py_compile collectors\proc_collector.py
python -m py_compile collectors\dmesg_collector.py
python -m py_compile collectors\journal_collector.py
python -m py_compile collectors\audit_collector.py
python -m py_compile collectors\ebpf_collector.py
python -m py_compile normalization\normalizer.py
python -m py_compile detection\rules.py
python -m py_compile detection\integrity_detector.py
python -m py_compile detection\privilege_detector.py
python -m py_compile correlation\correlator.py
python -m py_compile reporting\reporter.py

# Test CLI
python main.py --help
python main.py --run-once
python main.py --show-alerts
```

### On Linux / Docker (full functional testing)

```bash
# Option A: Docker
docker build -t project-dume .
docker run --rm project-dume                                    # basic
docker run --rm project-dume python main.py --init-baseline -v  # create baseline
docker run --rm project-dume python main.py --run-once -v       # detect

# Option B: Direct on Linux (Kali / Ubuntu)
pip install -r requirements.txt
python main.py --init-baseline --verbose
python main.py --run-once --verbose
python main.py --show-alerts
```

## Docker/Linux Limitations

- Without `--privileged`, Docker containers see only container-scoped `/proc` and lack [dmesg](file:///d:/Projects/Project-Dume/Project-Dume/collectors/dmesg_collector.py#16-66)/`journalctl`/audit logs
- To expose host telemetry: `docker run --rm --privileged -v /proc:/host/proc:ro -v /var/log:/host/log:ro project-dume`
- Audit log (`/var/log/audit/audit.log`) requires `auditd` running on the host
