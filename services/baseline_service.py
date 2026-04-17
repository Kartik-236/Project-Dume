"""
Project DUME — Baseline Service
"""

import os
from typing import Any

import config
from baseline.baseline_manager import load_baseline


def get_baseline_summary() -> dict[str, Any]:
    """Return baseline status and key stats."""
    exists = os.path.isfile(config.BASELINE_PATH)
    if not exists:
        return {"exists": False, "timestamp": None, "modules": 0, "sysctls": 0, "binary_hashes": 0}

    mtime = os.path.getmtime(config.BASELINE_PATH)
    from datetime import datetime, timezone
    ts = datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat()

    bl = load_baseline()
    if bl is None:
        return {"exists": True, "timestamp": ts, "modules": 0, "sysctls": 0, "binary_hashes": 0}

    return {
        "exists": True,
        "timestamp": ts,
        "modules": len(bl.get("kernel_modules", [])),
        "sysctls": len(bl.get("sysctls", {})),
        "binary_hashes": sum(1 for v in bl.get("binary_hashes", {}).values() if v),
        "detail": bl,
    }
