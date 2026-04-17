# Project DUME

**Secure Kernel Linux Hardening Against Rootkits and Privilege Escalation**

A lightweight, modular, kernel-aware host security framework for Linux that creates trusted baselines, collects runtime telemetry, detects suspicious kernel integrity drift and privilege escalation, and generates risk-scored alerts with a web dashboard.

> **Phase 2** — Working model for testing, experiments, and research.

---

## Architecture

```
Trusted Baseline Creation
  -> Continuous Telemetry Collection
    -> Event Normalization
      -> Kernel Integrity & Privilege Analysis
        -> Risk Scoring & Event Correlation
          -> Alert Generation
            -> Evidence Logging & Reporting
              -> Web Dashboard
```

## Repository Structure

```
project-dume/
├── main.py                     CLI pipeline orchestrator
├── app.py                      FastAPI web application
├── config.py                   Central configuration
├── Dockerfile                  Linux container (web mode)
├── docker-compose.yml          App + PostgreSQL services
├── requirements.txt            Python dependencies
│
├── baseline/
│   └── baseline_manager.py     Kernel module / sysctl / binary baselines
│
├── collectors/
│   ├── proc_collector.py       Process enumeration + deleted-exe + caps
│   ├── dmesg_collector.py      Kernel ring buffer
│   ├── journal_collector.py    systemd journal
│   ├── audit_collector.py      /var/log/audit/audit.log parser
│   └── ebpf_collector.py       Stub for future eBPF extension
│
├── normalization/
│   └── normalizer.py           Common event schema conversion
│
├── detection/
│   ├── rules.py                Scoring constants & shared helpers
│   ├── integrity_detector.py   Kernel integrity drift analysis
│   └── privilege_detector.py   Privilege escalation detection
│
├── correlation/
│   └── correlator.py           Risk scoring & event correlation
│
├── reporting/
│   └── reporter.py             Console, JSON, and summary output
│
├── services/
│   ├── pipeline_service.py     Shared pipeline logic (CLI + web)
│   ├── baseline_service.py     Baseline summary
│   ├── detection_service.py    Run/alert/finding queries
│   ├── report_service.py       Report file listing
│   └── health_service.py       System health checks
│
├── storage/
│   ├── db.py                   DB abstraction (PostgreSQL + SQLite)
│   └── event_store.py          Runs, events, alerts, findings tables
│
├── web/
│   └── api_routes.py           FastAPI API endpoints
│
├── frontend/                   Static dashboard pages
│   ├── index.html              Dashboard
│   ├── baseline.html           Baseline detail
│   ├── runs.html               Run history
│   ├── alerts.html             Alert list
│   ├── findings.html           Finding list
│   ├── reports.html            JSON report list
│   ├── health.html             System health
│   ├── style.css               Dark theme
│   └── app.js                  API fetch logic
│
├── scripts/
│   ├── run_kali.sh             Kali launcher (web/cli/status/stop/logs)
│   └── stop_kali.sh            Quick stop
│
└── docs/
    ├── synopsis.md
    └── architecture.md
```

## Kali Quick Start

```bash
# Make scripts executable
chmod +x scripts/*.sh

# Start web mode (Docker Compose with PostgreSQL)
./scripts/run_kali.sh web

# Check status
./scripts/run_kali.sh status

# View logs
./scripts/run_kali.sh logs

# Stop services
./scripts/run_kali.sh stop

# CLI sanity check
./scripts/run_kali.sh cli
```

## CLI Usage (Local Linux)

```bash
pip install -r requirements.txt

python main.py --init-baseline --verbose
python main.py --run-once --verbose
python main.py --show-alerts
```

## Web Mode (Local)

```bash
pip install -r requirements.txt

# SQLite fallback (no PostgreSQL needed)
uvicorn app:app --host 0.0.0.0 --port 8000

# Visit http://localhost:8000
```

## Docker Compose

```bash
docker compose up --build        # Start app + postgres
docker compose down              # Stop
docker compose logs -f app       # Tail logs
```

Dashboard: http://localhost:8000

## Database

| Mode | Backend | Config |
|---|---|---|
| Docker Compose | PostgreSQL | `DATABASE_BACKEND=postgres` (default in compose) |
| Local / standalone | SQLite | `DATABASE_BACKEND=sqlite` (default) |

To force SQLite in any environment: `export DATABASE_BACKEND=sqlite`

## Phase 2 Detection Capabilities

**Kernel Integrity (rootkit-adjacent):**
- Baseline module drift (new / missing modules)
- Suspicious module names (diamorphine, reptile, etc.)
- Module load from suspicious paths (/tmp, /dev/shm, /home)
- sysctl weakening / drift
- Binary hash drift
- Deleted-but-running privileged executables

**Privilege Escalation:**
- Abnormal euid==0 (with expanded system allowlist)
- Suspicious sudo / pkexec / insmod / modprobe usage
- Suspicious command-line paths
- Full capability set detection (CapEff)
- Deleted-running executables

**Correlation:**
- Privilege + module activity bonus
- sysctl drift + suspicious command bonus
- Deleted-exe + privilege indicator bonus

## Limitations

- Without `--privileged` Docker mode, collectors see container-scoped data only
- eBPF is stub-only in this phase
- Does NOT detect deep kernel memory rootkits or syscall hook tampering
- Not a production EDR — academic research prototype

## Testing Suggestions (safe lab)

```bash
# After starting web mode, trigger detections:
curl -X POST http://localhost:8000/api/run-baseline
curl -X POST http://localhost:8000/api/run-detection

# On Kali, simulate detectable behaviors:
sudo ls                          # triggers sudo detection
sudo modprobe dummy              # module + privilege correlation
```

## License

Academic project — see your institution's policies on redistribution.
