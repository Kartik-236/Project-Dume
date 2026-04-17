"""
Project DUME — Event & Alert Storage (Phase 2)
Stores runs, events, alerts, and findings via the unified DB abstraction.
Supports both SQLite and PostgreSQL.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any

from storage.db import adapt_sql, fetchall_dicts, get_connection, is_postgres

log = logging.getLogger("dume.storage")


# ── Schema initialisation ────────────────────────────────────────────────

_SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp                TEXT    NOT NULL,
    raw_events_count         INTEGER NOT NULL DEFAULT 0,
    normalized_events_count  INTEGER NOT NULL DEFAULT 0,
    integrity_findings_count INTEGER NOT NULL DEFAULT 0,
    privilege_findings_count INTEGER NOT NULL DEFAULT 0,
    total_findings_count     INTEGER NOT NULL DEFAULT 0,
    total_score              INTEGER NOT NULL DEFAULT 0,
    severity                 TEXT,
    summary                  TEXT,
    recommended_action       TEXT,
    baseline_present         INTEGER NOT NULL DEFAULT 0,
    payload                  TEXT
);

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      INTEGER,
    timestamp   TEXT    NOT NULL,
    source      TEXT    NOT NULL,
    event_type  TEXT,
    payload     TEXT    NOT NULL,
    created_at  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      INTEGER,
    timestamp   TEXT    NOT NULL,
    severity    TEXT    NOT NULL,
    total_score INTEGER NOT NULL,
    summary     TEXT,
    payload     TEXT    NOT NULL,
    created_at  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id        INTEGER,
    finding_type  TEXT    NOT NULL,
    severity      TEXT    NOT NULL,
    score         INTEGER NOT NULL DEFAULT 0,
    description   TEXT,
    evidence      TEXT,
    created_at    TEXT    NOT NULL
);
"""

_PG_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id                       SERIAL PRIMARY KEY,
    timestamp                TEXT    NOT NULL,
    raw_events_count         INTEGER NOT NULL DEFAULT 0,
    normalized_events_count  INTEGER NOT NULL DEFAULT 0,
    integrity_findings_count INTEGER NOT NULL DEFAULT 0,
    privilege_findings_count INTEGER NOT NULL DEFAULT 0,
    total_findings_count     INTEGER NOT NULL DEFAULT 0,
    total_score              INTEGER NOT NULL DEFAULT 0,
    severity                 TEXT,
    summary                  TEXT,
    recommended_action       TEXT,
    baseline_present         INTEGER NOT NULL DEFAULT 0,
    payload                  TEXT
);

CREATE TABLE IF NOT EXISTS events (
    id          SERIAL PRIMARY KEY,
    run_id      INTEGER,
    timestamp   TEXT    NOT NULL,
    source      TEXT    NOT NULL,
    event_type  TEXT,
    payload     TEXT    NOT NULL,
    created_at  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    id          SERIAL PRIMARY KEY,
    run_id      INTEGER,
    timestamp   TEXT    NOT NULL,
    severity    TEXT    NOT NULL,
    total_score INTEGER NOT NULL,
    summary     TEXT,
    payload     TEXT    NOT NULL,
    created_at  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id            SERIAL PRIMARY KEY,
    run_id        INTEGER,
    finding_type  TEXT    NOT NULL,
    severity      TEXT    NOT NULL,
    score         INTEGER NOT NULL DEFAULT 0,
    description   TEXT,
    evidence      TEXT,
    created_at    TEXT    NOT NULL
);
"""


def init_db() -> None:
    """Create all tables if they don't exist."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        schema = _PG_SCHEMA if is_postgres() else _SQLITE_SCHEMA
        for stmt in schema.strip().split(";"):
            stmt = stmt.strip()
            if stmt:
                cur.execute(stmt)
        conn.commit()
        log.info("Database initialised (%s)", "postgres" if is_postgres() else "sqlite")
    finally:
        conn.close()


# ── Runs ─────────────────────────────────────────────────────────────────

def save_run(run_data: dict[str, Any]) -> int:
    """Persist a run record. Returns the new run id."""
    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()
    sql = adapt_sql(
        "INSERT INTO runs (timestamp, raw_events_count, normalized_events_count, "
        "integrity_findings_count, privilege_findings_count, total_findings_count, "
        "total_score, severity, summary, recommended_action, baseline_present, payload) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    try:
        cur = conn.cursor()
        cur.execute(sql, (
            run_data.get("timestamp", now),
            run_data.get("raw_events_count", 0),
            run_data.get("normalized_events_count", 0),
            run_data.get("integrity_findings_count", 0),
            run_data.get("privilege_findings_count", 0),
            run_data.get("total_findings_count", 0),
            run_data.get("total_score", 0),
            run_data.get("severity"),
            run_data.get("summary"),
            run_data.get("recommended_action"),
            1 if run_data.get("baseline_present") else 0,
            json.dumps(run_data),
        ))
        if is_postgres():
            cur.execute("SELECT currval(pg_get_serial_sequence('runs','id'))")
            run_id = cur.fetchone()[0]
        else:
            run_id = cur.lastrowid
        conn.commit()
        return run_id
    finally:
        conn.close()


def fetch_recent_runs(limit: int = 20) -> list[dict[str, Any]]:
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(adapt_sql(
            "SELECT id, timestamp, total_score, severity, total_findings_count, "
            "summary, baseline_present FROM runs ORDER BY id DESC LIMIT ?"
        ), (limit,))
        return fetchall_dicts(cur)
    finally:
        conn.close()


def fetch_run_by_id(run_id: int) -> dict[str, Any] | None:
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(adapt_sql("SELECT payload FROM runs WHERE id = ?"), (run_id,))
        rows = fetchall_dicts(cur)
        if rows:
            return json.loads(rows[0]["payload"])
        return None
    finally:
        conn.close()


def count_runs() -> int:
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) AS cnt FROM runs")
        return fetchall_dicts(cur)[0]["cnt"]
    finally:
        conn.close()


# ── Events ───────────────────────────────────────────────────────────────

def save_events(events: list[dict[str, Any]], run_id: int | None = None) -> int:
    """Persist a batch of normalized events. Returns count saved."""
    if not events:
        return 0
    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()
    sql = adapt_sql(
        "INSERT INTO events (run_id, timestamp, source, event_type, payload, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)"
    )
    try:
        cur = conn.cursor()
        for ev in events:
            cur.execute(sql, (
                run_id,
                ev.get("timestamp", now),
                ev.get("source", "unknown"),
                ev.get("event_type"),
                json.dumps(ev),
                now,
            ))
        conn.commit()
        return len(events)
    finally:
        conn.close()


# ── Alerts ───────────────────────────────────────────────────────────────

def save_alert(alert: dict[str, Any], run_id: int | None = None) -> None:
    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()
    sql = adapt_sql(
        "INSERT INTO alerts (run_id, timestamp, severity, total_score, summary, payload, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)"
    )
    try:
        cur = conn.cursor()
        cur.execute(sql, (
            run_id,
            alert.get("timestamp", now),
            alert.get("severity", "unknown"),
            alert.get("total_score", 0),
            alert.get("summary", ""),
            json.dumps(alert),
            now,
        ))
        conn.commit()
    finally:
        conn.close()


def fetch_recent_alerts(limit: int = 10) -> list[dict[str, Any]]:
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(adapt_sql(
            "SELECT id, run_id, timestamp, severity, total_score, summary "
            "FROM alerts ORDER BY id DESC LIMIT ?"
        ), (limit,))
        return fetchall_dicts(cur)
    finally:
        conn.close()


def count_alerts() -> int:
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) AS cnt FROM alerts")
        return fetchall_dicts(cur)[0]["cnt"]
    finally:
        conn.close()


# ── Findings ─────────────────────────────────────────────────────────────

def save_findings(findings: list[dict[str, Any]], run_id: int | None = None) -> int:
    if not findings:
        return 0
    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()
    sql = adapt_sql(
        "INSERT INTO findings (run_id, finding_type, severity, score, description, evidence, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)"
    )
    try:
        cur = conn.cursor()
        for f in findings:
            cur.execute(sql, (
                run_id,
                f.get("finding_type", "unknown"),
                f.get("severity", "unknown"),
                f.get("score", 0),
                f.get("description", ""),
                json.dumps(f.get("evidence")),
                now,
            ))
        conn.commit()
        return len(findings)
    finally:
        conn.close()


def fetch_recent_findings(limit: int = 50) -> list[dict[str, Any]]:
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(adapt_sql(
            "SELECT id, run_id, finding_type, severity, score, description, created_at "
            "FROM findings ORDER BY id DESC LIMIT ?"
        ), (limit,))
        return fetchall_dicts(cur)
    finally:
        conn.close()


def count_findings() -> int:
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) AS cnt FROM findings")
        return fetchall_dicts(cur)[0]["cnt"]
    finally:
        conn.close()
