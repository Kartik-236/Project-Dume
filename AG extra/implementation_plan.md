# Phase 2 — Implementation Plan

Upgrade the validated MVP into a working model with dashboard, PostgreSQL, service layer, and detection upgrades. All changes are additive — existing CLI and SQLite MVP remain functional.

---

## Proposed Changes

### 1. DB Abstraction & Config

#### [MODIFY] [config.py](file:///d:/Projects/Project-Dume/Project-Dume/config.py)
Add: `DATABASE_BACKEND` (env-driven: `postgres` or `sqlite`), PostgreSQL env vars (`PGHOST`, `PGPORT`, `PGDATABASE`, `PGUSER`, `PGPASSWORD`), new scoring constants (`SCORE_DELETED_EXE`, `SCORE_SUSPICIOUS_CAPS`, `CORRELATION_DELETED_PLUS_PRIV`).

#### [NEW] [storage/db.py](file:///d:/Projects/Project-Dume/Project-Dume/storage/db.py)
Unified DB abstraction with `get_connection()` that returns either a SQLite or PostgreSQL connection based on config. Uses `?` → `%s` placeholder adaptation for cross-backend SQL. PostgreSQL uses `psycopg2`.

#### [MODIFY] [storage/event_store.py](file:///d:/Projects/Project-Dume/Project-Dume/storage/event_store.py)
- Use `storage.db` abstraction instead of direct `sqlite3`
- Add `runs` and `findings` tables
- Add: `save_run()`, `fetch_recent_runs()`, `save_findings()`, `fetch_recent_findings()`, `fetch_run_by_id()`, `count_runs()`, `count_alerts()`, `count_findings()`

---

### 2. Service Layer (all new)

#### [NEW] services/pipeline_service.py
`run_baseline()` → returns structured result. `run_detection_cycle()` → runs full pipeline, returns structured run result (replaces [do_run_once](file:///d:/Projects/Project-Dume/Project-Dume/main.py#75-140) logic in main.py). Both return dicts, not print-only.

#### [NEW] services/baseline_service.py
`get_baseline_summary()` — baseline exists?, timestamp, module count, sysctl count, hash count.

#### [NEW] services/detection_service.py
`get_run_history()`, `get_recent_alerts()`, `get_recent_findings()` — thin wrappers around event_store for API.

#### [NEW] services/report_service.py
`get_reports_list()` — scans `reporting/output/` for JSON files, returns name/size/mtime. `get_report_content(filename)` — safe read with path-traversal protection.

#### [NEW] services/health_service.py
`get_health_status()` — checks: platform, Docker detection, /proc/modules readable, sysctl readable, dmesg, journalctl, audit log, baseline file, DB reachable, report dir.

---

### 3. Detection Upgrades

#### [MODIFY] [collectors/proc_collector.py](file:///d:/Projects/Project-Dume/Project-Dume/collectors/proc_collector.py)
Add per-process: `exe_path` via `proc.exe()`, `exe_deleted` flag (check if `/proc/{pid}/exe` → [(deleted)](file:///d:/Projects/Project-Dume/Project-Dume/main.py#159-185)), `capabilities` from `/proc/{pid}/status` CapEff (best-effort Linux-only).

#### [MODIFY] [detection/rules.py](file:///d:/Projects/Project-Dume/Project-Dume/detection/rules.py)
Add: `SCORE_DELETED_EXE`, `SCORE_SUSPICIOUS_CAPS`, `DANGEROUS_CAPABILITIES` set, expanded `SUSPICIOUS_MODULE_NAMES`.

#### [MODIFY] [detection/privilege_detector.py](file:///d:/Projects/Project-Dume/Project-Dume/detection/privilege_detector.py)
Add checks: deleted-exe detection (`finding_type="deleted_running_exe"`), suspicious capability flags, expanded `_SYSTEM_ROOT_NAMES` allowlist.

#### [MODIFY] [detection/integrity_detector.py](file:///d:/Projects/Project-Dume/Project-Dume/detection/integrity_detector.py)
Add: detect deleted-but-running privileged executables from proc events (cross-references with privilege domain).

#### [MODIFY] [correlation/correlator.py](file:///d:/Projects/Project-Dume/Project-Dume/correlation/correlator.py)
Add correlation bonus: `deleted_running_exe` + priv indicators → higher confidence.

---

### 4. Web Layer

#### [NEW] [app.py](file:///d:/Projects/Project-Dume/Project-Dume/app.py)
FastAPI app. Mounts `frontend/` as static files at `/`. Includes `web.api_routes` router at `/api`. Startup event initializes DB.

#### [NEW] [web/api_routes.py](file:///d:/Projects/Project-Dume/Project-Dume/web/api_routes.py)
Endpoints: `GET /api/status`, `POST /api/run-baseline`, `POST /api/run-detection`, `GET /api/runs`, `GET /api/alerts`, `GET /api/findings`, `GET /api/reports`, `GET /api/reports/{filename}`, `GET /api/health`, `GET /api/runs/{id}`, `GET /api/alerts/{id}`.

#### [MODIFY] [main.py](file:///d:/Projects/Project-Dume/Project-Dume/main.py)
Refactor [do_run_once](file:///d:/Projects/Project-Dume/Project-Dume/main.py#75-140) to call `pipeline_service.run_detection_cycle()` internally so the logic is shared. CLI behavior preserved exactly.

---

### 5. Frontend (all new — `frontend/` directory)

7 HTML pages + `style.css` + `app.js`. Dark theme, screenshot-friendly, no frameworks.

| File | Content |
|---|---|
| `index.html` | Dashboard: baseline status, last scan, scores, counts, action buttons |
| `baseline.html` | Baseline detail: modules, sysctls, hashes |
| `runs.html` | Run history table |
| `alerts.html` | Alert list with severity/score |
| `findings.html` | Findings list with type/severity/evidence |
| `reports.html` | JSON report file list |
| `health.html` | Collector/system health checks |
| `style.css` | Dark theme with cards, tables, buttons |
| `app.js` | [fetch()](file:///d:/Projects/Project-Dume/Project-Dume/storage/event_store.py#97-107) calls to `/api/*`, DOM rendering |

---

### 6. Packaging

#### [MODIFY] requirements.txt
```
psutil
fastapi
uvicorn[standard]
psycopg2-binary
```

#### [MODIFY] Dockerfile
Add `CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]`. Keep `EXPOSE 8000`.

#### [MODIFY] docker-compose.yml
Add `postgres` service. Set env vars for app service. Expose `8000:8000`. No privileged, no Redis.

#### [MODIFY] README.md
Add Phase 2 sections: web mode, Docker Compose, PostgreSQL, SQLite fallback, testing workflow.

---

## Verification Plan

### Automated
```powershell
# On Windows — syntax check
Get-ChildItem -Recurse -Filter *.py | ForEach-Object {
  python -m py_compile $_.FullName
}
python main.py --help
python main.py --show-alerts
```

### Docker
```bash
docker compose up --build
# Visit http://localhost:8000
curl http://localhost:8000/api/status
curl -X POST http://localhost:8000/api/run-baseline
curl -X POST http://localhost:8000/api/run-detection
curl http://localhost:8000/api/health
```
