"""
Project DUME — Privilege Escalation Detector (Phase 2)
Detects suspicious privilege usage from normalized process and log telemetry.
Adds: deleted-exe detection, capability checks, expanded system allowlist.
"""

import logging
from typing import Any

from detection import rules

log = logging.getLogger("dume.detection.privilege")

# Process names typically running as root that we don't flag
_SYSTEM_ROOT_NAMES: set[str] = {
    # Init / systemd
    "systemd", "init", "systemd-logind", "systemd-udevd",
    "systemd-journald", "systemd-resolved", "systemd-timesyncd",
    "systemd-networkd", "systemd-oomd",
    # Kernel threads
    "kthreadd", "ksoftirqd", "kworker", "migration",
    "rcu_sched", "rcu_bh", "rcu_preempt", "watchdog",
    "kswapd", "kcompactd", "khugepaged", "kdevtmpfs",
    "kauditd", "irq/",
    # Core daemons
    "sshd", "cron", "crond", "atd",
    "agetty", "login", "getty",
    "dbus-daemon", "dbus-broker",
    "rsyslogd", "syslogd",
    "NetworkManager", "dhclient", "dhcpcd", "wpa_supplicant",
    "polkitd", "accounts-daemon",
    # Container runtimes
    "dockerd", "containerd", "containerd-shim", "runc",
    # Package managers (running as root is normal)
    "apt", "dpkg", "yum", "dnf", "pacman", "rpm",
    # Other common safe root processes
    "snapd", "udisksd", "cupsd", "bluetoothd", "avahi-daemon",
    "irqbalance", "thermald", "acpid", "multipathd",
    "python", "python3", "uvicorn",  # our own app in Docker
}


def analyse(normalized_events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Scan normalized events for privilege escalation indicators."""
    findings: list[dict[str, Any]] = []

    for ev in normalized_events:
        source = ev.get("source", "")
        name = (ev.get("process_name") or "").lower()
        euid = ev.get("euid")
        uid = ev.get("uid")
        msg = (ev.get("message") or "").lower()
        cmdline = msg
        metadata = ev.get("metadata", {})

        # ── 1. Abnormal euid==0 ──────────────────────────────────────
        if source == "proc" and euid == 0:
            # Skip kernel threads and known safe daemons
            if name and not _is_safe_root(name):
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
                        "cmdline": msg[:300],
                    },
                ))

        # ── 2. Deleted-but-running executable ────────────────────────
        if source == "proc" and metadata.get("exe_deleted"):
            findings.append(rules.make_finding(
                finding_type="deleted_running_exe",
                severity="high",
                score=rules.SCORE_DELETED_EXE,
                description=f"Process '{name}' (pid={ev.get('pid')}) running from "
                            f"deleted executable: {metadata.get('exe_path', '?')}",
                evidence={
                    "pid": ev.get("pid"),
                    "process_name": ev.get("process_name"),
                    "exe_path": metadata.get("exe_path"),
                    "euid": euid,
                },
            ))

        # ── 3. Suspicious capabilities ───────────────────────────────
        capeff = metadata.get("capeff")
        if source == "proc" and rules.has_full_capabilities(capeff):
            if euid != 0 or (name and not _is_safe_root(name)):
                findings.append(rules.make_finding(
                    finding_type="suspicious_capabilities",
                    severity="medium",
                    score=rules.SCORE_SUSPICIOUS_CAPS,
                    description=f"Process '{name}' (pid={ev.get('pid')}) has full "
                                f"capability set (CapEff={capeff})",
                    evidence={
                        "pid": ev.get("pid"),
                        "process_name": ev.get("process_name"),
                        "capeff": capeff,
                        "euid": euid,
                    },
                ))

        # ── 4. Suspicious command usage ──────────────────────────────
        for sus_cmd in rules.SUSPICIOUS_COMMANDS:
            if sus_cmd in cmdline:
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
                        "message": msg[:300],
                        "pid": ev.get("pid"),
                    },
                ))
                break

        # ── 5. Suspicious path in cmdline ────────────────────────────
        if source == "proc" and rules.is_suspicious_path(cmdline):
            findings.append(rules.make_finding(
                finding_type="suspicious_cmdline_path",
                severity="medium",
                score=rules.SCORE_SUSPICIOUS_CMD,
                description="Process cmdline references suspicious path",
                evidence={
                    "pid": ev.get("pid"),
                    "cmdline": msg[:300],
                },
            ))

    # Deduplicate by (finding_type, pid, description prefix)
    seen: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for f in findings:
        key = "|".join([
            f["finding_type"],
            str(f.get("evidence", {}).get("pid", "")),
            f["description"][:80],
        ])
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    log.info("Privilege detector produced %d findings (%d before dedup)",
             len(deduped), len(findings))
    return deduped


def _is_safe_root(name: str) -> bool:
    """Check if a process name matches the system root allowlist."""
    if name in _SYSTEM_ROOT_NAMES:
        return True
    # Match prefix-based entries (e.g. "kworker/0:1")
    return any(name.startswith(prefix) for prefix in (
        "kworker", "irq/", "migration/", "ksoftirqd/",
        "rcu_", "watchdog/", "cpuhp/", "idle",
    ))
