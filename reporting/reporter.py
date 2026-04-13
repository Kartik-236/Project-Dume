"""
Project DUME — Reporter
Outputs alerts to console, JSON files, and generates incident summaries.
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

import config

log = logging.getLogger("dume.reporting")


def print_alert_to_console(alert: dict[str, Any]) -> None:
    """Pretty-print an alert to stdout for demo / operator visibility."""
    sev = alert.get("severity", "unknown").upper()
    score = alert.get("total_score", 0)
    ts = alert.get("timestamp", "")
    findings = alert.get("findings", [])

    bar = "=" * 60
    print(f"\n{bar}")
    print(f"  PROJECT DUME — ALERT")
    print(f"  Severity : {sev}")
    print(f"  Score    : {score}")
    print(f"  Time     : {ts}")
    print(f"  Action   : {alert.get('recommended_action', 'alert_only')}")
    print(f"{bar}")
    print(f"  Summary  : {alert.get('summary', 'N/A')}")
    print(f"  Findings : {len(findings)}")
    for i, f in enumerate(findings, 1):
        print(f"    [{i}] ({f.get('severity','?')}, score={f.get('score',0)}) "
              f"{f.get('finding_type','?')}: {f.get('description','')}")
    print(bar + "\n")


def save_alert_json(
    alert: dict[str, Any],
    output_dir: str | None = None,
) -> str:
    """Write alert to a timestamped JSON file. Returns the file path."""
    output_dir = output_dir or config.REPORT_OUTPUT_DIR
    os.makedirs(output_dir, exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = f"alert_{ts}.json"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w") as f:
        json.dump(alert, f, indent=2, default=str)

    log.info("Alert saved to %s", filepath)
    return filepath


def generate_incident_summary(alert: dict[str, Any]) -> str:
    """Return a concise human-readable incident summary string."""
    lines = [
        f"Incident Summary — {alert.get('timestamp', 'N/A')}",
        f"Overall severity: {alert.get('severity', 'unknown').upper()}",
        f"Risk score: {alert.get('total_score', 0)}",
        f"Recommended action: {alert.get('recommended_action', 'alert_only')}",
        "",
        "Findings:",
    ]
    for i, f in enumerate(alert.get("findings", []), 1):
        lines.append(
            f"  {i}. [{f.get('severity','?')}] {f.get('finding_type','?')} "
            f"(score={f.get('score',0)}): {f.get('description','')}"
        )
    lines.append("")
    lines.append(f"Summary: {alert.get('summary', 'N/A')}")
    return "\n".join(lines)
