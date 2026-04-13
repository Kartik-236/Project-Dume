"""
Project DUME — Audit Log Collector
Best-effort parsing of /var/log/audit/audit.log for suspicious events.
"""

import logging
import os
import re
from datetime import datetime, timezone
from typing import Any

import config

log = logging.getLogger("dume.collectors.audit")

_AUDIT_LOG_PATH = "/var/log/audit/audit.log"

# Regex to extract key=value pairs from audit lines
_KV_RE = re.compile(r'(\w+)=(".*?"|\S+)')


def _parse_audit_line(line: str) -> dict[str, str] | None:
    """Parse a single audit log line into a dict of key-value pairs."""
    # Typical line: type=SYSCALL msg=audit(1234567890.123:456): ...
    fields = dict(_KV_RE.findall(line))
    if not fields:
        return None
    # Extract type from the beginning if present
    if "type" not in fields:
        m = re.match(r"type=(\S+)", line)
        if m:
            fields["type"] = m.group(1)
    return fields


def collect_audit_events(
    audit_path: str = _AUDIT_LOG_PATH,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    """Read recent audit log entries and extract suspicious events.

    Returns an empty list with a logged warning if the audit log is missing
    or inaccessible (common in Docker / non-audit environments).
    """
    limit = limit or config.AUDIT_LINE_LIMIT
    now = datetime.now(timezone.utc).isoformat()

    if not os.path.isfile(audit_path):
        log.warning("Audit log not found at %s — skipping audit collection", audit_path)
        return []

    try:
        with open(audit_path, "r") as f:
            lines = f.readlines()
    except PermissionError:
        log.warning("Permission denied reading %s — try running as root", audit_path)
        return []
    except OSError as exc:
        log.warning("Could not read audit log: %s", exc)
        return []

    # Take only the tail
    lines = lines[-limit:]

    events: list[dict[str, Any]] = []
    allowed_types = set(config.AUDIT_EVENT_TYPES)
    sus_cmds_lower = [c.lower() for c in config.SUSPICIOUS_COMMANDS]

    for raw_line in lines:
        raw_line = raw_line.strip()
        if not raw_line:
            continue

        fields = _parse_audit_line(raw_line)
        if fields is None:
            continue

        event_type = fields.get("type", "").upper()
        if event_type not in allowed_types:
            continue

        # Check for suspicious indicators in the full line
        line_lower = raw_line.lower()
        matched = [c for c in sus_cmds_lower if c in line_lower]

        events.append({
            "timestamp": now,
            "source": "audit",
            "audit_type": event_type,
            "uid": fields.get("uid"),
            "euid": fields.get("euid"),
            "exe": fields.get("exe", "").strip('"'),
            "comm": fields.get("comm", "").strip('"'),
            "message": raw_line[:500],  # cap length
            "matched_keywords": matched,
            "fields": fields,
        })

    log.info("Collected %d audit events (from %d lines)", len(events), len(lines))
    return events
