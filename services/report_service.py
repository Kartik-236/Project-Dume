"""
Project DUME — Report Service
Lists and reads JSON report files from reporting/output.
"""

import os
from datetime import datetime, timezone
from typing import Any

import config


def get_reports_list() -> list[dict[str, Any]]:
    """List JSON report files in the output directory."""
    out_dir = config.REPORT_OUTPUT_DIR
    if not os.path.isdir(out_dir):
        return []

    reports = []
    for name in sorted(os.listdir(out_dir), reverse=True):
        if not name.endswith(".json"):
            continue
        fpath = os.path.join(out_dir, name)
        stat = os.stat(fpath)
        reports.append({
            "filename": name,
            "size_bytes": stat.st_size,
            "modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
        })
    return reports


def get_report_content(filename: str) -> dict[str, Any] | None:
    """Read a report file safely. Returns None on invalid/missing file.

    Prevents path traversal by stripping directory components.
    """
    # Security: only allow bare filenames
    safe_name = os.path.basename(filename)
    if safe_name != filename or ".." in filename:
        return None

    fpath = os.path.join(config.REPORT_OUTPUT_DIR, safe_name)
    if not os.path.isfile(fpath):
        return None

    import json
    try:
        with open(fpath, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None
