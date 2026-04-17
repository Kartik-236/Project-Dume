"""
Project DUME — FastAPI Application (Phase 2)

Serves the dashboard frontend and API endpoints.
Run with: uvicorn app:app --host 0.0.0.0 --port 8000
"""

import os
import logging

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from storage.event_store import init_db
from web.api_routes import router as api_router

log = logging.getLogger("dume.app")

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_FRONTEND_DIR = os.path.join(_BASE_DIR, "frontend")

app = FastAPI(
    title="Project DUME",
    description="Secure Kernel Linux Hardening Against Rootkits and Privilege Escalation",
    version="2.0.0",
)

# ── API routes (must be registered BEFORE static mount) ──────────────────
app.include_router(api_router)

# ── Explicit page routes ─────────────────────────────────────────────────
# Serve HTML pages at clean URLs without interfering with /api/*

_PAGES = {
    "/": "index.html",
    "/baseline": "baseline.html",
    "/runs": "runs.html",
    "/alerts": "alerts.html",
    "/findings": "findings.html",
    "/reports": "reports.html",
    "/health": "health.html",
}


def _make_page_handler(html_file: str):
    async def handler():
        return FileResponse(os.path.join(_FRONTEND_DIR, html_file))
    return handler


for path, html_file in _PAGES.items():
    app.get(path, include_in_schema=False)(_make_page_handler(html_file))

# ── Static assets (CSS, JS) under /static ────────────────────────────────
app.mount("/static", StaticFiles(directory=_FRONTEND_DIR), name="static")


# ── Startup event ────────────────────────────────────────────────────────
@app.on_event("startup")
def on_startup():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )
    init_db()
    log.info("Project DUME Phase 2 started")
