"""
Project DUME — SQLite Event & Alert Storage
Stores normalized events and correlated alerts persistently.
"""

import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import Any


def _connect(db_path: str) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str) -> None:
    """Create events and alerts tables if they don't exist."""
    conn = _connect(db_path)
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT    NOT NULL,
                source      TEXT    NOT NULL,
                event_type  TEXT,
                payload     TEXT    NOT NULL,
                created_at  TEXT    NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT    NOT NULL,
                severity    TEXT    NOT NULL,
                total_score INTEGER NOT NULL,
                summary     TEXT,
                payload     TEXT    NOT NULL,
                created_at  TEXT    NOT NULL
            )
        """)
        conn.commit()
    finally:
        conn.close()


def save_events(db_path: str, events: list[dict[str, Any]]) -> int:
    """Persist a batch of normalized events. Returns count saved."""
    if not events:
        return 0
    conn = _connect(db_path)
    now = datetime.now(timezone.utc).isoformat()
    try:
        for ev in events:
            conn.execute(
                "INSERT INTO events (timestamp, source, event_type, payload, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    ev.get("timestamp", now),
                    ev.get("source", "unknown"),
                    ev.get("event_type"),
                    json.dumps(ev),
                    now,
                ),
            )
        conn.commit()
        return len(events)
    finally:
        conn.close()


def save_alert(db_path: str, alert: dict[str, Any]) -> None:
    """Persist a single correlated alert."""
    conn = _connect(db_path)
    now = datetime.now(timezone.utc).isoformat()
    try:
        conn.execute(
            "INSERT INTO alerts (timestamp, severity, total_score, summary, payload, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                alert.get("timestamp", now),
                alert.get("severity", "unknown"),
                alert.get("total_score", 0),
                alert.get("summary", ""),
                json.dumps(alert),
                now,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def fetch_recent_alerts(db_path: str, limit: int = 10) -> list[dict[str, Any]]:
    """Return the most recent alerts from the DB."""
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            "SELECT payload FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [json.loads(row["payload"]) for row in rows]
    finally:
        conn.close()
