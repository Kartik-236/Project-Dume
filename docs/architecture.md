# Project DUME — Architecture

## Module Overview

| Module | Responsibility |
|---|---|
| `config.py` | Central configuration — paths, thresholds, suspicious indicators |
| `baseline/baseline_manager.py` | Snapshot & compare kernel modules, sysctls, binary hashes |
| `collectors/proc_collector.py` | Enumerate processes via psutil, flag suspicious indicators |
| `collectors/dmesg_collector.py` | Parse kernel ring buffer for security-relevant messages |
| `collectors/journal_collector.py` | Query systemd journal for security-relevant log entries |
| `collectors/audit_collector.py` | Parse `/var/log/audit/audit.log` for audit events |
| `collectors/ebpf_collector.py` | Stub — future eBPF kernel probe integration |
| `normalization/normalizer.py` | Convert heterogeneous raw events into a common schema |
| `detection/rules.py` | Scoring constants, suspicious indicators, shared helpers |
| `detection/integrity_detector.py` | Detect kernel module drift, sysctl weakening, binary tampering |
| `detection/privilege_detector.py` | Detect abnormal root execution, suspicious commands/paths |
| `correlation/correlator.py` | Sum scores, apply correlation bonuses, assign severity tier |
| `reporting/reporter.py` | Console alert output, JSON file export, incident summaries |
| `storage/event_store.py` | SQLite persistence for normalised events and alerts |
| `main.py` | CLI orchestrator — wires the full pipeline |

## Data Flow

```
┌──────────────────────────────────────────────────────────────┐
│                        main.py (CLI)                         │
└────┬────────────┬────────────┬───────────┬───────────────────┘
     │            │            │           │
     ▼            ▼            ▼           ▼
 baseline/   collectors/   collectors/  collectors/
 baseline_   proc_        dmesg_       journal_ / audit_
 manager     collector    collector    collector
     │            │            │           │
     │            └──────┬─────┘───────────┘
     │                   ▼
     │          normalization/normalizer
     │                   │
     │                   ▼
     │          storage/event_store ──► SQLite (events)
     │                   │
     ▼                   ▼
 Baseline         detection/
 Comparison       integrity_detector + privilege_detector
     │                   │
     └─────────┬─────────┘
               ▼
       correlation/correlator
               │
               ▼
       reporting/reporter  ──► Console + JSON
               │
               ▼
       storage/event_store ──► SQLite (alerts)
```

## Event Schema

All raw events are normalised into this common structure:

```json
{
  "timestamp": "ISO 8601",
  "source": "proc | dmesg | journal | audit",
  "event_type": "string",
  "process_name": "string | null",
  "pid": "int | null",
  "ppid": "int | null",
  "uid": "int | null",
  "euid": "int | null",
  "target": "string | null",
  "message": "string",
  "risk_tags": ["list of tags"],
  "metadata": {}
}
```

## Finding Schema

Detectors produce findings with this structure:

```json
{
  "finding_type": "new_kernel_module | sysctl_drift | ...",
  "severity": "low | medium | high | critical",
  "score": 15,
  "description": "Human-readable description",
  "evidence": {}
}
```

## Alert Schema (Correlator Output)

```json
{
  "timestamp": "ISO 8601",
  "total_score": 45,
  "severity": "medium",
  "findings": [],
  "summary": "Narrative summary",
  "recommended_action": "alert_only"
}
```

## Graceful Degradation

Every collector handles missing commands, files, or permissions by logging a warning and returning an empty list. The pipeline always completes — partial data produces partial (but valid) results.
