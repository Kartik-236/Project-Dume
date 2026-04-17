"""
Project DUME — Pipeline Service
Shared backend logic for CLI and web API.
"""

import logging
from datetime import datetime, timezone
from typing import Any

import config
from baseline.baseline_manager import (
    compare_current_to_baseline,
    create_baseline,
    load_baseline,
)
from collectors.audit_collector import collect_audit_events
from collectors.dmesg_collector import collect_dmesg_events
from collectors.journal_collector import collect_journal_events
from collectors.proc_collector import collect_process_events
from correlation.correlator import correlate
from detection.integrity_detector import analyse as integrity_analyse
from detection.privilege_detector import analyse as privilege_analyse
from normalization.normalizer import normalize_events
from reporting.reporter import save_alert_json
from storage.event_store import (
    init_db,
    save_alert,
    save_events,
    save_findings,
    save_run,
)

log = logging.getLogger("dume.services.pipeline")


def run_baseline() -> dict[str, Any]:
    """Create/update baseline and return a structured summary."""
    bl = create_baseline()
    mods = len(bl.get("kernel_modules", []))
    sysctls = len(bl.get("sysctls", {}))
    bins = sum(1 for v in bl.get("binary_hashes", {}).values() if v)
    return {
        "status": "ok",
        "message": f"Baseline saved: {mods} modules, {sysctls} sysctls, {bins} binary hashes",
        "path": config.BASELINE_PATH,
        "modules": mods,
        "sysctls": sysctls,
        "binary_hashes": bins,
    }


def run_detection_cycle() -> dict[str, Any]:
    """Execute a full detection cycle and return structured results.

    This is the shared implementation used by both CLI and web API.
    """
    init_db()

    # Baseline
    baseline = load_baseline()
    baseline_present = baseline is not None
    if not baseline_present:
        create_baseline()
        baseline = load_baseline()
        baseline_present = True

    # Collect
    raw_events: list[dict[str, Any]] = []
    raw_events.extend(collect_process_events())
    raw_events.extend(collect_dmesg_events())
    raw_events.extend(collect_journal_events())
    raw_events.extend(collect_audit_events())

    # Normalize
    normalized = normalize_events(raw_events)

    # Baseline comparison
    drift = compare_current_to_baseline(baseline)

    # Detect
    integrity_findings = integrity_analyse(drift, normalized)
    privilege_findings = privilege_analyse(normalized)
    all_findings = integrity_findings + privilege_findings

    # Correlate
    alert = correlate(all_findings)
    score = alert["total_score"]
    severity = alert["severity"]

    # Build run record
    now = datetime.now(timezone.utc).isoformat()
    run_data: dict[str, Any] = {
        "timestamp": now,
        "raw_events_count": len(raw_events),
        "normalized_events_count": len(normalized),
        "integrity_findings_count": len(integrity_findings),
        "privilege_findings_count": len(privilege_findings),
        "total_findings_count": len(all_findings),
        "total_score": score,
        "severity": severity,
        "summary": alert.get("summary", ""),
        "recommended_action": alert.get("recommended_action", "alert_only"),
        "baseline_present": baseline_present,
    }

    # Persist
    run_id = save_run(run_data)
    save_events(normalized, run_id=run_id)
    save_findings(all_findings, run_id=run_id)

    alert_saved = False
    report_path = None
    if score >= config.ALERT_THRESHOLD:
        save_alert(alert, run_id=run_id)
        report_path = save_alert_json(alert)
        alert_saved = True

    run_data["run_id"] = run_id
    run_data["alert_saved"] = alert_saved
    run_data["report_path"] = report_path
    run_data["findings"] = all_findings

    return run_data
