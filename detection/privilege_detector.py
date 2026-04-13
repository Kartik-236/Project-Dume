"""
Project DUME — Privilege Escalation Detector
Detects suspicious privilege usage from normalized process and log telemetry.
"""

import logging
from typing import Any

from detection import rules

log = logging.getLogger("dume.detection.privilege")

# Process names typically running as root that we don't flag
_SYSTEM_ROOT_NAMES: set[str] = {
    "systemd", "init", "kthreadd", "ksoftirqd", "kworker",
    "migration", "rcu_sched", "rcu_bh", "watchdog", "sshd",
    "cron", "agetty", "login", "dbus-daemon", "dockerd",
    "containerd", "journald", "udevd", "rsyslogd", "NetworkManager",
    "polkitd", "accounts-daemon", "snapd",
}


def analyse(normalized_events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Scan normalized events for privilege escalation indicators.

    Returns a list of structured findings.
    """
    findings: list[dict[str, Any]] = []

    for ev in normalized_events:
        source = ev.get("source", "")
        name = (ev.get("process_name") or "").lower()
        euid = ev.get("euid")
        uid = ev.get("uid")
        msg = (ev.get("message") or "").lower()
        cmdline = msg  # for proc events, message == cmdline
        risk_tags = ev.get("risk_tags", [])

        # ── 1. Abnormal euid==0 ──────────────────────────────────────
        if source == "proc" and euid == 0:
            if name and name not in _SYSTEM_ROOT_NAMES and not name.startswith("kworker"):
                findings.append(rules.make_finding(
                    finding_type="abnormal_root_euid",
                    severity="medium",
                    score=rules.SCORE_SUSPICIOUS_PRIV,
                    description=f"Process '{name}' (pid={ev.get('pid')}) running "
                                f"as euid=0 with user context",
                    evidence={
                        "pid": ev.get("pid"),
                        "process_name": ev.get("process_name"),
                        "uid": uid,
                        "euid": euid,
                        "cmdline": ev.get("message", "")[:300],
                    },
                ))

        # ── 2. Suspicious command usage ──────────────────────────────
        for sus_cmd in rules.SUSPICIOUS_COMMANDS:
            if sus_cmd in cmdline:
                # Avoid double-flagging if the process IS the command (e.g. sudo running = normal)
                if source == "proc" and name == sus_cmd:
                    continue
                findings.append(rules.make_finding(
                    finding_type="suspicious_command",
                    severity="medium",
                    score=rules.SCORE_SUSPICIOUS_CMD,
                    description=f"Suspicious command '{sus_cmd}' detected "
                                f"in {source} event",
                    evidence={
                        "source": source,
                        "matched_command": sus_cmd,
                        "message": ev.get("message", "")[:300],
                        "pid": ev.get("pid"),
                    },
                ))
                break  # one finding per event

        # ── 3. Suspicious path in cmdline ────────────────────────────
        if source == "proc" and rules.is_suspicious_path(cmdline):
            findings.append(rules.make_finding(
                finding_type="suspicious_cmdline_path",
                severity="medium",
                score=rules.SCORE_SUSPICIOUS_CMD,
                description=f"Process cmdline references suspicious path",
                evidence={
                    "pid": ev.get("pid"),
                    "cmdline": ev.get("message", "")[:300],
                },
            ))

    # Deduplicate by (finding_type, pid/message) to avoid noise
    seen: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for f in findings:
        key = (
            f["finding_type"],
            str(f.get("evidence", {}).get("pid", "")),
            f["description"][:80],
        )
        k = "|".join(key)
        if k not in seen:
            seen.add(k)
            deduped.append(f)

    log.info("Privilege detector produced %d findings (%d before dedup)",
             len(deduped), len(findings))
    return deduped
