"""
Project DUME — Central Configuration
All tuneable values live here for easy adjustment.
"""

import os

# Resolve paths relative to this file's directory (project root)
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ── Paths ────────────────────────────────────────────────────────────────
DB_PATH = os.path.join(_BASE_DIR, "storage", "events.db")
BASELINE_PATH = os.path.join(_BASE_DIR, "baseline", "baseline.json")
REPORT_OUTPUT_DIR = os.path.join(_BASE_DIR, "reporting", "output")

# ── Database backend ─────────────────────────────────────────────────────
# Set DATABASE_BACKEND=postgres to use PostgreSQL, otherwise falls back to sqlite
DATABASE_BACKEND = os.environ.get("DATABASE_BACKEND", "sqlite").lower()

# PostgreSQL connection (used when DATABASE_BACKEND=postgres)
PGHOST = os.environ.get("PGHOST", "localhost")
PGPORT = int(os.environ.get("PGPORT", "5432"))
PGDATABASE = os.environ.get("PGDATABASE", "dume")
PGUSER = os.environ.get("PGUSER", "dume")
PGPASSWORD = os.environ.get("PGPASSWORD", "dume")

# ── Collector limits ─────────────────────────────────────────────────────
DMESG_LINE_LIMIT = 200
JOURNAL_LINE_LIMIT = 200
AUDIT_LINE_LIMIT = 500

# ── Monitored sysctl keys ───────────────────────────────────────────────
MONITORED_SYSCTLS: list[str] = [
    "kernel.kptr_restrict",
    "kernel.dmesg_restrict",
    "kernel.kexec_load_disabled",
    "kernel.modules_disabled",
    "kernel.unprivileged_bpf_disabled",
]

# ── Trusted privileged binaries (checked for hash drift) ─────────────────
TRUSTED_BINARIES: list[str] = [
    "/usr/bin/sudo",
    "/usr/bin/pkexec",
    "/usr/sbin/modprobe",
    "/sbin/insmod",
]

# ── Suspicious indicators ───────────────────────────────────────────────
SUSPICIOUS_COMMANDS: list[str] = [
    "sudo", "pkexec", "insmod", "modprobe",
    "rmmod", "modinfo", "kmod",
]

SUSPICIOUS_PATHS: list[str] = [
    "/tmp", "/var/tmp", "/dev/shm", "/home",
]

# Keywords collectors search for in log lines
LOG_KEYWORDS: list[str] = [
    "module", "insmod", "modprobe", "taint",
    "audit", "denied", "sudo", "pkexec", "kernel",
]

# Audit log event types of interest
AUDIT_EVENT_TYPES: list[str] = [
    "EXECVE", "SYSCALL", "USER_CMD",
    "USER_ACCT", "USER_START", "USER_END",
]

# ── Scoring / thresholds ────────────────────────────────────────────────
SCORE_NEW_MODULE = 15
SCORE_MISSING_MODULE = 10
SCORE_SYSCTL_DRIFT = 20
SCORE_BINARY_HASH_DRIFT = 25
SCORE_SUSPICIOUS_PRIV = 15
SCORE_SUSPICIOUS_CMD = 10
SCORE_SUSPICIOUS_PATH_MODULE = 20
SCORE_DELETED_EXE = 25
SCORE_SUSPICIOUS_CAPS = 15

# Correlation bonus scores
CORRELATION_PRIV_PLUS_MODULE = 15
CORRELATION_SYSCTL_PLUS_CMD = 10
CORRELATION_DELETED_PLUS_PRIV = 20

# Severity tiers (cumulative score thresholds)
SEVERITY_THRESHOLDS: dict[str, int] = {
    "critical": 80,
    "high": 50,
    "medium": 25,
    "low": 0,
}

# Alert threshold — only generate an alert when total score >= this
ALERT_THRESHOLD = 10
