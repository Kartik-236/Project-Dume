# Project DUME

**Secure Kernel Linux Hardening Against Rootkits and Privilege Escalation**

A lightweight, modular, kernel-aware host security framework for Linux that creates trusted baselines, collects runtime telemetry, detects suspicious kernel integrity drift and privilege escalation, and generates risk-scored alerts.

> **Status:** Academic MVP / seminar-capstone prototype — not a production EDR.

---

## Architecture

```
Trusted Baseline Creation
  → Continuous Telemetry Collection
    → Event Normalization
      → Kernel Integrity & Privilege Analysis
        → Risk Scoring & Event Correlation
          → Alert Generation
            → Evidence Logging & Reporting
```

## Repository Structure

```
project-dume/
├── main.py                     CLI pipeline orchestrator
├── config.py                   Central configuration
├── Dockerfile                  Linux container for execution
├── docker-compose.yml          Optional Compose service
├── requirements.txt            Python dependencies (psutil only)
│
├── baseline/
│   └── baseline_manager.py     Kernel module / sysctl / binary baselines
│
├── collectors/
│   ├── proc_collector.py       Process enumeration (psutil)
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
├── storage/
│   └── event_store.py          SQLite persistence (events & alerts)
│
└── docs/
    ├── synopsis.md             Brief project summary
    └── architecture.md         Module overview & data flow
```

## Quick Start

### Prerequisites

- Python 3.10+
- Linux (Kali, Ubuntu, Debian, etc.) for full functionality
- Docker (optional, for containerised execution)

### Run Locally on Linux

```bash
# Install dependencies
pip install -r requirements.txt

# Create a trusted baseline snapshot
python main.py --init-baseline --verbose

# Run one detection cycle
python main.py --run-once --verbose

# View stored alerts
python main.py --show-alerts
```

### Run in Docker

```bash
# Build the image
docker build -t project-dume .

# Basic run (container-scoped telemetry only)
docker run --rm project-dume

# With host kernel visibility (requires elevated access)
docker run --rm --privileged \
    -v /proc:/host/proc:ro \
    -v /var/log:/host/log:ro \
    project-dume
```

Or with Docker Compose:

```bash
docker compose up --build
```

### CLI Reference

| Flag | Description |
|---|---|
| `--init-baseline` | Create or update the trusted baseline snapshot |
| `--run-once` | Execute a single detection cycle |
| `--show-alerts` | Display recent alerts from the database |
| `--verbose` / `-v` | Enable debug-level logging |

Flags can be combined: `python main.py --init-baseline --run-once --verbose`

## Limitations

- **Docker:** Without `--privileged` and bind mounts, collectors only see container-level data. The pipeline still runs gracefully with partial results.
- **Windows development:** The project targets Linux. On Windows, syntax and import checks pass but telemetry collectors return empty datasets.
- **Audit log:** Requires `auditd` to be running and `/var/log/audit/audit.log` to be readable. Many Docker images lack this.
- **eBPF:** Stub only in MVP — no eBPF probes are attached.
- **Not a full EDR:** This is a focused academic prototype, not a comprehensive endpoint detection and response system.

## MVP Scope

- ✅ Trusted baseline (kernel modules, sysctls, binary hashes)
- ✅ Multi-source telemetry (proc, dmesg, journalctl, audit)
- ✅ Common event schema normalisation
- ✅ Kernel integrity drift detection
- ✅ Privilege escalation detection
- ✅ Weighted risk scoring with correlation bonuses
- ✅ SQLite event and alert persistence
- ✅ Console and JSON alert reporting
- ✅ Dockerised execution

## Future Scope

- Live eBPF kernel probes for real-time module loading / execve visibility
- Continuous daemon mode with configurable scan intervals
- YARA rule integration for in-memory module scanning
- Network telemetry collection
- Web dashboard for alert review
- Integration with SIEM / syslog forwarding
- Automated response actions (quarantine, module unload)

## License

Academic project — see your institution's policies on redistribution.
