"""
Project DUME — Health Service
System and collector health checks.
"""

import os
import platform
import shutil
import subprocess
from typing import Any

import config
from storage.db import is_postgres


def get_health_status() -> dict[str, Any]:
    """Run health checks and return structured results."""
    checks: dict[str, Any] = {}

    # Platform
    checks["platform"] = platform.platform()
    checks["python_version"] = platform.python_version()

    # Docker detection (best effort)
    checks["running_in_docker"] = (
        os.path.isfile("/.dockerenv")
        or os.environ.get("container") == "docker"
    )

    # /proc/modules
    checks["proc_modules_readable"] = os.access("/proc/modules", os.R_OK)

    # sysctl readable
    sysctl_ok = False
    for key in config.MONITORED_SYSCTLS[:1]:
        path = "/proc/sys/" + key.replace(".", "/")
        if os.access(path, os.R_OK):
            sysctl_ok = True
            break
    checks["sysctl_readable"] = sysctl_ok

    # dmesg accessible
    checks["dmesg_available"] = shutil.which("dmesg") is not None
    if checks["dmesg_available"]:
        try:
            r = subprocess.run(["dmesg", "--help"], capture_output=True, timeout=3)
            checks["dmesg_accessible"] = r.returncode == 0
        except Exception:
            checks["dmesg_accessible"] = False
    else:
        checks["dmesg_accessible"] = False

    # journalctl available
    checks["journalctl_available"] = shutil.which("journalctl") is not None

    # audit log
    checks["audit_log_present"] = os.path.isfile("/var/log/audit/audit.log")

    # baseline
    checks["baseline_exists"] = os.path.isfile(config.BASELINE_PATH)

    # database
    checks["database_backend"] = "postgres" if is_postgres() else "sqlite"
    try:
        from storage.db import get_connection
        conn = get_connection()
        conn.close()
        checks["database_reachable"] = True
    except Exception as exc:
        checks["database_reachable"] = False
        checks["database_error"] = str(exc)

    # report directory
    checks["report_dir_exists"] = os.path.isdir(config.REPORT_OUTPUT_DIR)

    return checks
