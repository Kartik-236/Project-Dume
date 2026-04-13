"""
Project DUME — Event Correlator / Risk Scorer
Merges findings from all detectors, applies correlation bonuses,
and assigns an overall severity tier.
"""

import logging
from datetime import datetime, timezone
from typing import Any

import config
from detection.rules import score_to_severity

log = logging.getLogger("dume.correlation")


def correlate(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Correlate a set of detector findings into a single scored alert.

    Returns a dict with:
        timestamp, total_score, severity, findings, summary, recommended_action
    """
    if not findings:
        return _build_result(0, findings, "No findings in this cycle.")

    total = sum(f.get("score", 0) for f in findings)

    # ── Correlation bonuses ──────────────────────────────────────────
    types = {f.get("finding_type", "") for f in findings}

    priv_types = {"abnormal_root_euid", "suspicious_command", "suspicious_cmdline_path"}
    module_types = {"new_kernel_module", "suspicious_module_path", "missing_kernel_module"}

    has_priv = bool(types & priv_types)
    has_module = bool(types & module_types)
    has_sysctl = "sysctl_drift" in types

    if has_priv and has_module:
        total += config.CORRELATION_PRIV_PLUS_MODULE
        log.info("Correlation bonus: privilege + module findings (+%d)",
                 config.CORRELATION_PRIV_PLUS_MODULE)

    if has_sysctl and has_priv:
        total += config.CORRELATION_SYSCTL_PLUS_CMD
        log.info("Correlation bonus: sysctl drift + privilege findings (+%d)",
                 config.CORRELATION_SYSCTL_PLUS_CMD)

    summary_parts = [f"{f['finding_type']}: {f['description']}" for f in findings[:5]]
    summary = "; ".join(summary_parts)
    if len(findings) > 5:
        summary += f" ... and {len(findings) - 5} more"

    return _build_result(total, findings, summary)


def _build_result(
    total_score: int,
    findings: list[dict[str, Any]],
    summary: str,
) -> dict[str, Any]:
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_score": total_score,
        "severity": score_to_severity(total_score),
        "findings": findings,
        "summary": summary,
        "recommended_action": "alert_only",
    }
