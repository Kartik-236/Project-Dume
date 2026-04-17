"""
Project DUME — Database Abstraction Layer
Provides a unified connection interface for SQLite and PostgreSQL.
All backend-specific SQL adaptation is isolated here.
"""

import os
import sqlite3
import logging
from typing import Any

import config

log = logging.getLogger("dume.storage.db")

_backend = config.DATABASE_BACKEND  # "sqlite" or "postgres"


def _pg_available() -> bool:
    try:
        import psycopg2  # noqa: F401
        return True
    except ImportError:
        return False


def get_connection() -> Any:
    """Return a DB-API 2.0 connection (sqlite3 or psycopg2).

    Caller is responsible for closing the connection.
    """
    if _backend == "postgres" and _pg_available():
        import psycopg2
        import psycopg2.extras
        conn = psycopg2.connect(
            host=config.PGHOST,
            port=config.PGPORT,
            dbname=config.PGDATABASE,
            user=config.PGUSER,
            password=config.PGPASSWORD,
        )
        conn.autocommit = False
        return conn
    else:
        if _backend == "postgres":
            log.warning("psycopg2 not installed — falling back to SQLite")
        db_path = config.DB_PATH
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        return conn


def is_postgres() -> bool:
    """Return True if the active backend is PostgreSQL."""
    return _backend == "postgres" and _pg_available()


def adapt_sql(sql: str) -> str:
    """Adapt SQL placeholder syntax for the active backend.

    SQLite uses '?', PostgreSQL uses '%s'.
    Write all SQL with '?' placeholders; call this before execute().
    """
    if is_postgres():
        return sql.replace("?", "%s")
    return sql


def fetchall_dicts(cursor: Any) -> list[dict[str, Any]]:
    """Convert cursor results to a list of dicts regardless of backend."""
    columns = [desc[0] for desc in cursor.description] if cursor.description else []
    return [dict(zip(columns, row)) for row in cursor.fetchall()]
