"""
Project DUME — Integrity Detector
Detects kernel integrity drift by analysing baseline comparison results
and module-related telemetry events.
"""

import logging
from typing import Any

from detection import rules

log = logging.getLogger("dume.detection.integrity")


def analyse(
    baseline_drift: list[dict[str, Any]],
    normalized_events: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Run integrity checks and return a list of findings.

    Args:
        baseline_drift: output of baseline_manager.compare_current_to_baseline()
        normalized_events: optional normalized telemetry (used for module-load heuristics)
    """
    findings: list[dict[str, Any]] = []

    # ── Baseline drift findings ──────────────────────────────────────
    for d in baseline_drift:
        dtype = d.get("drift_type", "")

        if dtype == "new_module":
            mod = d.get("key", "")
            score = rules.SCORE_NEW_MODULE
            severity = "medium"
            # Bump score if name matches known-suspicious modules
            if mod.lower() in [s.lower() for s in rules.SUSPICIOUS_MODULE_NAMES]:
                score += 20
                severity = "high"
            findings.append(rules.make_finding(
                finding_type="new_kernel_module",
                severity=severity,
                score=score,
                description=d.get("description", f"New module: {mod}"),
                evidence=d,
            ))

        elif dtype == "missing_module":
            findings.append(rules.make_finding(
                finding_type="missing_kernel_module",
                severity="low",
                score=rules.SCORE_MISSING_MODULE,
                description=d.get("description", "Module removed"),
                evidence=d,
            ))

        elif dtype == "sysctl_drift":
            findings.append(rules.make_finding(
                finding_type="sysctl_drift",
                severity="high",
                score=rules.SCORE_SYSCTL_DRIFT,
                description=d.get("description", "sysctl changed"),
                evidence=d,
            ))

        elif dtype == "binary_hash_drift":
            findings.append(rules.make_finding(
                finding_type="binary_hash_drift",
                severity="critical",
                score=rules.SCORE_BINARY_HASH_DRIFT,
                description=d.get("description", "Binary hash changed"),
                evidence=d,
            ))

    # ── Telemetry-based heuristics ───────────────────────────────────
    if normalized_events:
        for ev in normalized_events:
            msg = (ev.get("message") or "").lower()
            source = ev.get("source", "")

            # Detect module loads from suspicious paths (dmesg / journal)
            if source in ("dmesg", "journal"):
                if any(kw in msg for kw in ("insmod", "modprobe", "module")):
                    if rules.is_suspicious_path(msg):
                        findings.append(rules.make_finding(
                            finding_type="suspicious_module_path",
                            severity="high",
                            score=rules.SCORE_SUSPICIOUS_PATH_MODULE,
                            description=f"Module load from suspicious path detected in {source}",
                            evidence={"message": ev.get("message", "")[:500]},
                        ))

    log.info("Integrity detector produced %d findings", len(findings))
    return findings
