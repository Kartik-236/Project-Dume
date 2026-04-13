"""
Project DUME — journalctl Collector
Reads recent systemd journal entries and filters for security-relevant keywords.
"""

import logging
import subprocess
from datetime import datetime, timezone
from typing import Any

import config

log = logging.getLogger("dume.collectors.journal")


def collect_journal_events(limit: int | None = None) -> list[dict[str, Any]]:
    """Query journalctl for recent security-relevant log entries.

    Fails gracefully when journalctl is unavailable (e.g. non-systemd or Docker).
    """
    limit = limit or config.JOURNAL_LINE_LIMIT
    events: list[dict[str, Any]] = []
    now = datetime.now(timezone.utc).isoformat()

    try:
        result = subprocess.run(
            ["journalctl", "--no-pager", "-n", str(limit), "-q"],
            capture_output=True, text=True, timeout=10,
        )
    except FileNotFoundError:
        log.warning("journalctl not found — skipping journal collection")
        return []
    except subprocess.TimeoutExpired:
        log.warning("journalctl timed out")
        return []
    except PermissionError:
        log.warning("Permission denied running journalctl")
        return []

    if result.returncode != 0:
        log.warning("journalctl returned non-zero exit code: %s",
                     result.stderr.strip()[:200])
        # Still try to parse any output we got
        if not result.stdout.strip():
            return []

    keywords_lower = [kw.lower() for kw in config.LOG_KEYWORDS]

    for line in result.stdout.strip().splitlines():
        line_lower = line.lower()
        matched = [kw for kw in keywords_lower if kw in line_lower]
        if not matched:
            continue
        events.append({
            "timestamp": now,
            "source": "journal",
            "message": line.strip(),
            "matched_keywords": matched,
        })

    log.info("Collected %d journal events", len(events))
    return events
