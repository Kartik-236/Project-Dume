# Project DUME — Architecture (Phase 2)

## Module Overview

| Module | Responsibility |
|---|---|
| `config.py` | Central configuration — paths, thresholds, DB backend, suspicious indicators |
| `baseline/baseline_manager.py` | Snapshot & compare kernel modules, sysctls, binary hashes |
| `collectors/proc_collector.py` | Process enumeration via psutil + deleted-exe + CapEff |
| `collectors/dmesg_collector.py` | Parse kernel ring buffer for security-relevant messages |
| `collectors/journal_collector.py` | Query systemd journal for security-relevant logs |
| `collectors/audit_collector.py` | Parse `/var/log/audit/audit.log` for audit events |
| `collectors/ebpf_collector.py` | Stub — future eBPF kernel probe integration |
| `normalization/normalizer.py` | Convert raw events into common schema |
| `detection/rules.py` | Scoring constants, suspicious indicators, shared helpers |
| `detection/integrity_detector.py` | Module drift, sysctl weakening, binary/exe tampering |
| `detection/privilege_detector.py` | Abnormal root, suspicious commands, capabilities, deleted-exe |
| `correlation/correlator.py` | Score summation, correlation bonuses, severity assignment |
| `reporting/reporter.py` | Console output, JSON export, incident summaries |
| `storage/db.py` | Unified DB abstraction (PostgreSQL + SQLite) |
| `storage/event_store.py` | Runs, events, alerts, findings persistence |
| `services/pipeline_service.py` | Shared pipeline logic for CLI + web |
| `services/*_service.py` | Baseline, detection, report, health services |
| `web/api_routes.py` | FastAPI API endpoints |
| `app.py` | FastAPI application + static file serving |
| `main.py` | CLI orchestrator |

## Data Flow

```
                        main.py (CLI)  or  app.py (Web API)
                                    |
                         services/pipeline_service
                                    |
                    +---------------+---------------+
                    |               |               |
               baseline/       collectors/      collectors/
               baseline_       proc_ + dmesg_   journal_ + audit_
               manager         collector        collector
                    |               |               |
                    |               +-------+-------+
                    |                       |
                    |              normalization/normalizer
                    |                       |
                    |              storage/event_store --> DB (events)
                    |                       |
                    v                       v
                Baseline           detection/
                Comparison         integrity_ + privilege_
                    |                       |
                    +-----------+-----------+
                                |
                        correlation/correlator
                                |
                  +-------------+-------------+
                  |                           |
          reporting/reporter        storage/event_store
          (console + JSON)          --> DB (alerts, findings, runs)
```

## Database Schema

| Table | Key Columns |
|---|---|
| `runs` | id, timestamp, total_score, severity, total_findings_count, summary |
| `events` | id, run_id, timestamp, source, event_type, payload (JSON) |
| `alerts` | id, run_id, timestamp, severity, total_score, summary, payload (JSON) |
| `findings` | id, run_id, finding_type, severity, score, description, evidence (JSON) |

## Graceful Degradation

Every collector handles missing commands, files, or permissions by logging a warning and returning an empty list. The pipeline always completes — partial data produces partial (but valid) results.
