"""
Project DUME — Event Normalizer
Converts raw events from all collectors into a common schema.
"""

import logging
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger("dume.normalization")

# ── Common event schema ──────────────────────────────────────────────────
# {
#   "timestamp": str (ISO 8601),
#   "source": str,
#   "event_type": str,
#   "process_name": str | None,
#   "pid": int | None,
#   "ppid": int | None,
#   "uid": int | None,
#   "euid": int | None,
#   "target": str | None,
#   "message": str,
#   "risk_tags": list[str],
#   "metadata": dict,
# }


def _safe_int(val: Any) -> int | None:
    if val is None:
        return None
    try:
        return int(val)
    except (ValueError, TypeError):
        return None


def normalize_event(raw: dict[str, Any]) -> dict[str, Any]:
    """Convert a single raw event dict into the common schema.

    Tolerant of missing or malformed fields — never raises.
    """
    try:
        source = raw.get("source", "unknown")
        risk_tags: list[str] = list(raw.get("flags", []))

        # Build risk tags from matched keywords
        for kw in raw.get("matched_keywords", []):
            tag = f"keyword:{kw}"
            if tag not in risk_tags:
                risk_tags.append(tag)

        # Determine event_type
        event_type = raw.get("event_type") or raw.get("audit_type") or source

        # Build message
        message = raw.get("message") or raw.get("cmdline") or ""

        # Preserve extra fields in metadata
        _meta_skip = {
            "timestamp", "source", "event_type", "process_name", "pid",
            "ppid", "uid", "euid", "target", "message", "flags",
            "matched_keywords", "audit_type",
        }
        metadata = {k: v for k, v in raw.items() if k not in _meta_skip}

        return {
            "timestamp": raw.get("timestamp") or datetime.now(timezone.utc).isoformat(),
            "source": source,
            "event_type": event_type,
            "process_name": raw.get("process_name") or raw.get("comm"),
            "pid": _safe_int(raw.get("pid")),
            "ppid": _safe_int(raw.get("ppid")),
            "uid": _safe_int(raw.get("uid")),
            "euid": _safe_int(raw.get("euid")),
            "target": raw.get("target") or raw.get("exe"),
            "message": str(message)[:2000],
            "risk_tags": risk_tags,
            "metadata": metadata,
        }
    except Exception as exc:
        log.error("Failed to normalize event: %s — raw: %s", exc, repr(raw)[:300])
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "unknown",
            "event_type": "normalization_error",
            "process_name": None,
            "pid": None,
            "ppid": None,
            "uid": None,
            "euid": None,
            "target": None,
            "message": f"Normalization failed: {exc}",
            "risk_tags": [],
            "metadata": {},
        }


def normalize_events(raw_events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalize a batch of raw events, skipping None inputs."""
    return [normalize_event(e) for e in raw_events if isinstance(e, dict)]
