# Phase 2 — Walkthrough

## Files Added/Modified

| Action | File |
|---|---|
| **NEW** | [app.py](file:///d:/Projects/Project-Dume/Project-Dume/app.py) |
| **NEW** | [storage/db.py](file:///d:/Projects/Project-Dume/Project-Dume/storage/db.py) |
| **NEW** | [services/__init__.py](file:///d:/Projects/Project-Dume/Project-Dume/services/__init__.py), [pipeline_service.py](file:///d:/Projects/Project-Dume/Project-Dume/services/pipeline_service.py), [baseline_service.py](file:///d:/Projects/Project-Dume/Project-Dume/services/baseline_service.py), [detection_service.py](file:///d:/Projects/Project-Dume/Project-Dume/services/detection_service.py), [report_service.py](file:///d:/Projects/Project-Dume/Project-Dume/services/report_service.py), [health_service.py](file:///d:/Projects/Project-Dume/Project-Dume/services/health_service.py) |
| **NEW** | [web/__init__.py](file:///d:/Projects/Project-Dume/Project-Dume/web/__init__.py), [api_routes.py](file:///d:/Projects/Project-Dume/Project-Dume/web/api_routes.py) |
| **NEW** | `frontend/` — [index.html](file:///d:/Projects/Project-Dume/Project-Dume/frontend/index.html), [baseline.html](file:///d:/Projects/Project-Dume/Project-Dume/frontend/baseline.html), [runs.html](file:///d:/Projects/Project-Dume/Project-Dume/frontend/runs.html), [alerts.html](file:///d:/Projects/Project-Dume/Project-Dume/frontend/alerts.html), [findings.html](file:///d:/Projects/Project-Dume/Project-Dume/frontend/findings.html), [reports.html](file:///d:/Projects/Project-Dume/Project-Dume/frontend/reports.html), [health.html](file:///d:/Projects/Project-Dume/Project-Dume/frontend/health.html), [style.css](file:///d:/Projects/Project-Dume/Project-Dume/frontend/style.css), [app.js](file:///d:/Projects/Project-Dume/Project-Dume/frontend/app.js) |
| **NEW** | [scripts/run_kali.sh](file:///d:/Projects/Project-Dume/Project-Dume/scripts/run_kali.sh), [stop_kali.sh](file:///d:/Projects/Project-Dume/Project-Dume/scripts/stop_kali.sh) |
| MODIFIED | [config.py](file:///d:/Projects/Project-Dume/Project-Dume/config.py) — DB backend, PG vars, new scores |
| MODIFIED | [storage/event_store.py](file:///d:/Projects/Project-Dume/Project-Dume/storage/event_store.py) — DB abstraction, runs/findings tables |
| MODIFIED | [collectors/proc_collector.py](file:///d:/Projects/Project-Dume/Project-Dume/collectors/proc_collector.py) — deleted-exe, CapEff |
| MODIFIED | [detection/rules.py](file:///d:/Projects/Project-Dume/Project-Dume/detection/rules.py) — new scores, cap check, more modules |
| MODIFIED | [detection/privilege_detector.py](file:///d:/Projects/Project-Dume/Project-Dume/detection/privilege_detector.py) — deleted-exe, caps, expanded allowlist |
| MODIFIED | [detection/integrity_detector.py](file:///d:/Projects/Project-Dume/Project-Dume/detection/integrity_detector.py) — deleted privileged exe |
| MODIFIED | [correlation/correlator.py](file:///d:/Projects/Project-Dume/Project-Dume/correlation/correlator.py) — deleted-exe bonus |
| MODIFIED | [main.py](file:///d:/Projects/Project-Dume/Project-Dume/main.py) — uses pipeline_service, CLI preserved |
| MODIFIED | [requirements.txt](file:///d:/Projects/Project-Dume/Project-Dume/requirements.txt), [Dockerfile](file:///d:/Projects/Project-Dume/Project-Dume/Dockerfile), [docker-compose.yml](file:///d:/Projects/Project-Dume/Project-Dume/docker-compose.yml), [.gitignore](file:///d:/Projects/Project-Dume/Project-Dume/.gitignore) |
| MODIFIED | [README.md](file:///d:/Projects/Project-Dume/Project-Dume/README.md), [docs/synopsis.md](file:///d:/Projects/Project-Dume/Project-Dume/docs/synopsis.md), [docs/architecture.md](file:///d:/Projects/Project-Dume/Project-Dume/docs/architecture.md) |

## Verification Results (Windows)

| Check | Result |
|---|---|
| `py_compile` all .py files | Pass |
| `python main.py --help` | Pass — same CLI flags |
| `python main.py --run-once` | Pass — exit 0 |
| `python main.py --show-alerts` | Pass — exit 0 |

> **Note:** Old Phase 1 `events.db` must be deleted to pick up new schema. Docker Compose creates a fresh PostgreSQL DB automatically.

## Exact Commands

### Local CLI (Kali/Linux)
```bash
pip install -r requirements.txt
python main.py --init-baseline --verbose
python main.py --run-once --verbose
python main.py --show-alerts
```

### Local Web Mode (SQLite fallback)
```bash
pip install -r requirements.txt
# No PostgreSQL needed — uses SQLite by default
uvicorn app:app --host 0.0.0.0 --port 8000
# Visit http://localhost:8000
```

### Docker Compose (PostgreSQL)
```bash
docker compose up --build       # Start app + postgres
# Visit http://localhost:8000
curl http://localhost:8000/api/status
curl -X POST http://localhost:8000/api/run-baseline
curl -X POST http://localhost:8000/api/run-detection
docker compose down             # Stop
```

### Kali Scripts
```bash
chmod +x scripts/*.sh
./scripts/run_kali.sh web       # Full Docker startup with health check
./scripts/run_kali.sh status    # Check services
./scripts/run_kali.sh logs      # Tail logs
./scripts/run_kali.sh stop      # Stop services
./scripts/run_kali.sh cli       # CLI sanity check
```

### Force SQLite Fallback
```bash
export DATABASE_BACKEND=sqlite
uvicorn app:app --host 0.0.0.0 --port 8000
```

## Assumptions

- `psycopg2-binary` for PostgreSQL (as specified)
- Old Phase 1 `events.db` needs deletion for schema upgrade (Docker creates fresh DB)
- No `GET /api/alerts/{id}` — alerts have stable IDs but detail endpoint was unnecessary complexity for Phase 2
- `GET /api/runs/{id}` included — returns full run payload

## Safe Testing Suggestions

```bash
# After starting, trigger detections:
sudo ls                                 # sudo detection
sudo modprobe dummy                     # module + privilege correlation
echo 0 | sudo tee /proc/sys/kernel/kptr_restrict  # sysctl drift

# Then run detection:
curl -X POST http://localhost:8000/api/run-detection
# Check /alerts and /findings pages
```
