"""
Project DUME — dmesg Collector
Reads recent kernel ring-buffer messages and filters for security-relevant keywords.
"""

import logging
import subprocess
from datetime import datetime, timezone
from typing import Any

import config

log = logging.getLogger("dume.collectors.dmesg")


def collect_dmesg_events(limit: int | None = None) -> list[dict[str, Any]]:
    """Run dmesg and return raw events matching security keywords.

    Fails gracefully if dmesg is not available or permission is denied.
    """
    limit = limit or config.DMESG_LINE_LIMIT
    events: list[dict[str, Any]] = []
    now = datetime.now(timezone.utc).isoformat()

    try:
        result = subprocess.run(
            ["dmesg", "--time-format", "iso", "--nopager"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            # Some systems need plain dmesg without --time-format
            result = subprocess.run(
                ["dmesg"],
                capture_output=True, text=True, timeout=10,
            )
    except FileNotFoundError:
        log.warning("dmesg not found — skipping dmesg collection")
        return []
    except subprocess.TimeoutExpired:
        log.warning("dmesg timed out")
        return []
    except PermissionError:
        log.warning("Permission denied running dmesg")
        return []

    lines = result.stdout.strip().splitlines()
    # Take only the tail
    lines = lines[-limit:]

    keywords_lower = [kw.lower() for kw in config.LOG_KEYWORDS]

    for line in lines:
        line_lower = line.lower()
        matched = [kw for kw in keywords_lower if kw in line_lower]
        if not matched:
            continue
        events.append({
            "timestamp": now,
            "source": "dmesg",
            "message": line.strip(),
            "matched_keywords": matched,
        })

    log.info("Collected %d dmesg events (from %d lines)", len(events), len(lines))
    return events
