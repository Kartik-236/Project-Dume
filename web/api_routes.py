"""
Project DUME — API Routes (FastAPI)
All /api/* endpoints for the Phase 2 dashboard.
"""

from fastapi import APIRouter, HTTPException
from typing import Any

from services.pipeline_service import run_baseline, run_detection_cycle
from services.baseline_service import get_baseline_summary
from services.detection_service import (
    get_dashboard_summary,
    get_recent_alerts,
    get_recent_findings,
    get_run_detail,
    get_run_history,
)
from services.report_service import get_reports_list, get_report_content
from services.health_service import get_health_status

router = APIRouter(prefix="/api")


@router.get("/status")
def api_status() -> dict[str, Any]:
    """Dashboard summary: counts + baseline + last run info."""
    summary = get_dashboard_summary()
    baseline = get_baseline_summary()
    runs = get_run_history(limit=1)
    last_run = runs[0] if runs else None
    return {
        "project": "Project DUME",
        "phase": 2,
        "baseline": baseline,
        "last_run": last_run,
        **summary,
    }


@router.post("/run-baseline")
def api_run_baseline() -> dict[str, Any]:
    """Create or update the trusted baseline."""
    return run_baseline()


@router.post("/run-detection")
def api_run_detection() -> dict[str, Any]:
    """Execute a full detection cycle."""
    result = run_detection_cycle()
    # Don't send full findings list in response summary
    result.pop("findings", None)
    return result


@router.get("/runs")
def api_runs(limit: int = 20) -> list[dict[str, Any]]:
    return get_run_history(limit)


@router.get("/runs/{run_id}")
def api_run_detail(run_id: int) -> dict[str, Any]:
    detail = get_run_detail(run_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return detail


@router.get("/alerts")
def api_alerts(limit: int = 20) -> list[dict[str, Any]]:
    return get_recent_alerts(limit)


@router.get("/findings")
def api_findings(limit: int = 50) -> list[dict[str, Any]]:
    return get_recent_findings(limit)


@router.get("/reports")
def api_reports() -> list[dict[str, Any]]:
    return get_reports_list()


@router.get("/reports/{filename}")
def api_report_detail(filename: str) -> dict[str, Any]:
    content = get_report_content(filename)
    if content is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return content


@router.get("/health")
def api_health() -> dict[str, Any]:
    return get_health_status()
