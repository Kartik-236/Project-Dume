"""
Project DUME — Process Collector
Enumerates running processes via psutil and flags suspicious indicators.
"""

import logging
from datetime import datetime, timezone
from typing import Any

import psutil

import config

log = logging.getLogger("dume.collectors.proc")


def collect_process_events() -> list[dict[str, Any]]:
    """Return raw event dicts for currently running processes.

    Each event includes pid, ppid, name, uid/euid (if available),
    cmdline, and preliminary suspicious-indicator flags.
    """
    events: list[dict[str, Any]] = []
    now = datetime.now(timezone.utc).isoformat()

    for proc in psutil.process_iter(attrs=["pid", "ppid", "name", "username", "cmdline"]):
        try:
            info = proc.info
            pid = info.get("pid")
            ppid = info.get("ppid")
            name = info.get("name") or ""
            username = info.get("username") or ""
            cmdline_parts = info.get("cmdline") or []
            cmdline = " ".join(cmdline_parts)

            # uids is Linux-only; fetch separately with graceful fallback
            uid = None
            euid = None
            try:
                uids = proc.uids()  # (real, effective, saved)
                uid = uids.real
                euid = uids.effective
            except (AttributeError, psutil.AccessDenied, NotImplementedError):
                pass

            flags: list[str] = []

            # Flag root-euid for non-obvious system processes
            if euid == 0 and username not in ("root", ""):
                flags.append("euid_zero_non_root_user")

            # Flag suspicious commands in cmdline
            cmd_lower = cmdline.lower()
            for sus in config.SUSPICIOUS_COMMANDS:
                if sus in cmd_lower:
                    flags.append(f"suspicious_cmd:{sus}")
                    break

            events.append({
                "timestamp": now,
                "source": "proc",
                "pid": pid,
                "ppid": ppid,
                "process_name": name,
                "username": username,
                "uid": uid,
                "euid": euid,
                "cmdline": cmdline,
                "flags": flags,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    log.info("Collected %d process events", len(events))
    return events
