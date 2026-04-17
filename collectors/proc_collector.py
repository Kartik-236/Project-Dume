"""
Project DUME — Process Collector (Phase 2)
Enumerates running processes via psutil and flags suspicious indicators.
Adds deleted-exe detection and lightweight capability check.
"""

import logging
import os
from datetime import datetime, timezone
from typing import Any

import psutil

import config

log = logging.getLogger("dume.collectors.proc")


def _read_capeff(pid: int) -> str | None:
    """Read CapEff from /proc/<pid>/status (Linux only, best effort)."""
    try:
        with open(f"/proc/{pid}/status", "r") as f:
            for line in f:
                if line.startswith("CapEff:"):
                    return line.split(":")[1].strip()
    except (FileNotFoundError, PermissionError, OSError):
        pass
    return None


def _check_exe_deleted(pid: int) -> tuple[str | None, bool]:
    """Check if /proc/<pid>/exe points to a deleted file.

    Returns (exe_path, is_deleted).
    """
    link = f"/proc/{pid}/exe"
    try:
        target = os.readlink(link)
        deleted = target.endswith(" (deleted)")
        return target, deleted
    except (FileNotFoundError, PermissionError, OSError):
        return None, False


def collect_process_events() -> list[dict[str, Any]]:
    """Return raw event dicts for currently running processes.

    Each event includes pid, ppid, name, uid/euid (if available),
    cmdline, exe_path, exe_deleted flag, CapEff, and preliminary
    suspicious-indicator flags.
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

            # Exe path and deleted-exe check (Linux only)
            exe_path, exe_deleted = _check_exe_deleted(pid) if pid else (None, False)

            # Lightweight capability check (Linux only)
            capeff = _read_capeff(pid) if pid else None

            flags: list[str] = []

            # Flag root-euid for non-obvious system processes
            if euid == 0 and username not in ("root", ""):
                flags.append("euid_zero_non_root_user")

            # Flag deleted-but-running executable
            if exe_deleted:
                flags.append("exe_deleted")

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
                "exe_path": exe_path,
                "exe_deleted": exe_deleted,
                "capeff": capeff,
                "flags": flags,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    log.info("Collected %d process events", len(events))
    return events
