"""
Project DUME — Detection Rules (Centralized, Phase 2)
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
SCORE_DELETED_EXE = config.SCORE_DELETED_EXE
SCORE_SUSPICIOUS_CAPS = config.SCORE_SUSPICIOUS_CAPS

# ── Suspicious module-name heuristics ────────────────────────────────────
SUSPICIOUS_MODULE_NAMES: list[str] = [
    "diamorphine", "reptile", "suterusu", "bdvl",
    "hideproc", "rootkit", "lime", "kovid",
    "adore", "knark", "azazel", "jynx", "beurk",
]

# ── Dangerous capabilities (hex bitmask positions don't matter here, ───
#    we check for CapEff == full bitmask which means all caps granted)
# A CapEff of 000001ffffffffff (or similar full-set value) on a non-root-
# owned process is suspicious.
FULL_CAP_THRESHOLD = 0x000001ffffffffff  # common full-cap value


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


def has_full_capabilities(capeff: str | None) -> bool:
    """Check if a CapEff hex string indicates full (all) capabilities."""
    if not capeff:
        return False
    try:
        val = int(capeff, 16)
        return val >= FULL_CAP_THRESHOLD
    except ValueError:
        return False
