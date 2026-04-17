# Phase 2 — Task Checklist

## DB Abstraction & Storage
- [ ] Create `storage/db.py` — unified DB abstraction (postgres + sqlite)
- [ ] Update [config.py](file:///d:/Projects/Project-Dume/Project-Dume/config.py) — add DB backend, postgres env vars, new scoring constants
- [ ] Update [storage/event_store.py](file:///d:/Projects/Project-Dume/Project-Dume/storage/event_store.py) — use new DB abstraction, add runs/findings tables
- [ ] Add [__init__.py](file:///d:/Projects/Project-Dume/Project-Dume/storage/__init__.py) for new packages (services/, web/)

## Service Layer
- [ ] `services/pipeline_service.py` — run_baseline(), run_detection_cycle()
- [ ] `services/baseline_service.py` — get_baseline_summary()
- [ ] `services/detection_service.py` — get_runs(), get_alerts(), get_findings()
- [ ] `services/report_service.py` — get_reports_list()
- [ ] `services/health_service.py` — get_health_status()

## Detection Upgrades
- [ ] [collectors/proc_collector.py](file:///d:/Projects/Project-Dume/Project-Dume/collectors/proc_collector.py) — add deleted-exe and capability checks
- [ ] [detection/rules.py](file:///d:/Projects/Project-Dume/Project-Dume/detection/rules.py) — add new scoring constants and suspicious module names
- [ ] [detection/privilege_detector.py](file:///d:/Projects/Project-Dume/Project-Dume/detection/privilege_detector.py) — add capability/deleted-exe/setuid checks
- [ ] [detection/integrity_detector.py](file:///d:/Projects/Project-Dume/Project-Dume/detection/integrity_detector.py) — add deleted-exe finding type
- [ ] [correlation/correlator.py](file:///d:/Projects/Project-Dume/Project-Dume/correlation/correlator.py) — add deleted-exe correlation bonus

## Web Layer
- [ ] `app.py` — FastAPI app with static serving
- [ ] `web/api_routes.py` — all API endpoints
- [ ] Update [main.py](file:///d:/Projects/Project-Dume/Project-Dume/main.py) — keep CLI working, don't break imports

## Frontend
- [ ] `frontend/style.css` — dark theme
- [ ] `frontend/app.js` — API fetch logic
- [ ] `frontend/index.html` — dashboard
- [ ] `frontend/baseline.html`, `runs.html`, `alerts.html`, `findings.html`
- [ ] `frontend/reports.html`, `health.html`

## Packaging
- [ ] Update [requirements.txt](file:///d:/Projects/Project-Dume/Project-Dume/requirements.txt)
- [ ] Update [Dockerfile](file:///d:/Projects/Project-Dume/Project-Dume/Dockerfile)
- [ ] Update [docker-compose.yml](file:///d:/Projects/Project-Dume/Project-Dume/docker-compose.yml) (app + postgres)
- [ ] Update [README.md](file:///d:/Projects/Project-Dume/Project-Dume/README.md)

## Verification
- [ ] Syntax-check all Python files
- [ ] Test CLI --help, --run-once, --show-alerts
- [ ] Test FastAPI startup
