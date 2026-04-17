"""
Project DUME — Detection Service
Thin wrappers around event_store for API consumption.
"""

from typing import Any

from storage.event_store import (
    count_alerts,
    count_findings,
    count_runs,
    fetch_recent_alerts,
    fetch_recent_findings,
    fetch_recent_runs,
    fetch_run_by_id,
)


def get_run_history(limit: int = 20) -> list[dict[str, Any]]:
    return fetch_recent_runs(limit)


def get_run_detail(run_id: int) -> dict[str, Any] | None:
    return fetch_run_by_id(run_id)


def get_recent_alerts(limit: int = 20) -> list[dict[str, Any]]:
    return fetch_recent_alerts(limit)


def get_recent_findings(limit: int = 50) -> list[dict[str, Any]]:
    return fetch_recent_findings(limit)


def get_dashboard_summary() -> dict[str, Any]:
    """Aggregate counts for the dashboard."""
    return {
        "total_runs": count_runs(),
        "total_alerts": count_alerts(),
        "total_findings": count_findings(),
    }
