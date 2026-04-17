# Project DUME MVP Implementation

## Planning
- [x] Create implementation plan and get user approval

## Execution — Core Infrastructure
- [x] Implement [config.py](file:///d:/Projects/Project-Dume/Project-Dume/config.py) (central configuration)
- [x] Implement [storage/event_store.py](file:///d:/Projects/Project-Dume/Project-Dume/storage/event_store.py) (SQLite persistence)
- [x] Add [__init__.py](file:///d:/Projects/Project-Dume/Project-Dume/storage/__init__.py) to all package directories

## Execution — Baseline & Collection
- [x] Implement [baseline/baseline_manager.py](file:///d:/Projects/Project-Dume/Project-Dume/baseline/baseline_manager.py)
- [x] Implement [collectors/proc_collector.py](file:///d:/Projects/Project-Dume/Project-Dume/collectors/proc_collector.py)
- [x] Implement [collectors/dmesg_collector.py](file:///d:/Projects/Project-Dume/Project-Dume/collectors/dmesg_collector.py)
- [x] Implement [collectors/journal_collector.py](file:///d:/Projects/Project-Dume/Project-Dume/collectors/journal_collector.py)
- [x] Implement [collectors/audit_collector.py](file:///d:/Projects/Project-Dume/Project-Dume/collectors/audit_collector.py)
- [x] Create [collectors/ebpf_collector.py](file:///d:/Projects/Project-Dume/Project-Dume/collectors/ebpf_collector.py) (stub)

## Execution — Normalization & Detection
- [x] Implement [normalization/normalizer.py](file:///d:/Projects/Project-Dume/Project-Dume/normalization/normalizer.py)
- [x] Implement [detection/rules.py](file:///d:/Projects/Project-Dume/Project-Dume/detection/rules.py)
- [x] Implement [detection/integrity_detector.py](file:///d:/Projects/Project-Dume/Project-Dume/detection/integrity_detector.py)
- [x] Implement [detection/privilege_detector.py](file:///d:/Projects/Project-Dume/Project-Dume/detection/privilege_detector.py)

## Execution — Correlation & Reporting
- [x] Implement [correlation/correlator.py](file:///d:/Projects/Project-Dume/Project-Dume/correlation/correlator.py)
- [x] Implement [reporting/reporter.py](file:///d:/Projects/Project-Dume/Project-Dume/reporting/reporter.py)

## Execution — Orchestration & Packaging
- [x] Implement [main.py](file:///d:/Projects/Project-Dume/Project-Dume/main.py) (CLI pipeline)
- [x] Write [requirements.txt](file:///d:/Projects/Project-Dume/Project-Dume/requirements.txt)
- [x] Update [.gitignore](file:///d:/Projects/Project-Dume/Project-Dume/.gitignore)
- [x] Create [Dockerfile](file:///d:/Projects/Project-Dume/Project-Dume/Dockerfile) and [docker-compose.yml](file:///d:/Projects/Project-Dume/Project-Dume/docker-compose.yml)

## Execution — Documentation
- [x] Write [README.md](file:///d:/Projects/Project-Dume/Project-Dume/README.md)
- [x] Write [docs/synopsis.md](file:///d:/Projects/Project-Dume/Project-Dume/docs/synopsis.md)
- [x] Write [docs/architecture.md](file:///d:/Projects/Project-Dume/Project-Dume/docs/architecture.md)

## Verification
- [x] Syntax-check all Python files (py_compile)
- [x] Verify CLI --help, --show-alerts, --run-once
- [x] Fix Windows compat (proc_collector uids, Unicode)
