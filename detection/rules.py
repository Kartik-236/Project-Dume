"""
Project DUME — Detection Rules (Centralized)
Suspicious indicators, scoring constants, and shared helpers used by detectors.
"""

from typing import Any

import config

# ── Re-export config constants for convenience ───────────────────────────
SUSPICIOUS_COMMANDS: list[str] = config.SUSPICIOUS_COMMANDS
SUSPICIOUS_PATHS: list[str] = config.SUSPICIOUS_PATHS

# ── Severity labels ──────────────────────────────────────────────────────
SEVERITY_INFO = "info"
SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"
SEVERITY_CRITICAL = "critical"

# ── Score constants (mirrored from config for clarity) ───────────────────
SCORE_NEW_MODULE = config.SCORE_NEW_MODULE
SCORE_MISSING_MODULE = config.SCORE_MISSING_MODULE
SCORE_SYSCTL_DRIFT = config.SCORE_SYSCTL_DRIFT
SCORE_BINARY_HASH_DRIFT = config.SCORE_BINARY_HASH_DRIFT
SCORE_SUSPICIOUS_PRIV = config.SCORE_SUSPICIOUS_PRIV
SCORE_SUSPICIOUS_CMD = config.SCORE_SUSPICIOUS_CMD
SCORE_SUSPICIOUS_PATH_MODULE = config.SCORE_SUSPICIOUS_PATH_MODULE

# ── Suspicious module-name heuristics ────────────────────────────────────
# Short names, randomised-looking strings, known rootkit module names
SUSPICIOUS_MODULE_NAMES: list[str] = [
    "diamorphine", "reptile", "suterusu", "bdvl",
    "hideproc", "rootkit", "lime",
]


def score_to_severity(score: int) -> str:
    """Map a numeric score to a severity label."""
    for sev in ("critical", "high", "medium", "low"):
        if score >= config.SEVERITY_THRESHOLDS[sev]:
            return sev
    return SEVERITY_INFO


def make_finding(
    finding_type: str,
    severity: str,
    score: int,
    description: str,
    evidence: Any = None,
) -> dict[str, Any]:
    """Construct a standardised finding dict."""
    return {
        "finding_type": finding_type,
        "severity": severity,
        "score": score,
        "description": description,
        "evidence": evidence,
    }


def is_suspicious_path(path: str) -> bool:
    """Check whether a path starts with a known-suspicious directory."""
    p = path.lower()
    return any(p.startswith(sp) for sp in SUSPICIOUS_PATHS)
