"""
Project DUME — Baseline Manager
Creates, loads, and compares a trusted snapshot of kernel-related system state.
"""

import hashlib
import json
import logging
import os
import subprocess
from typing import Any

import config

log = logging.getLogger("dume.baseline")


# ── Internal helpers ─────────────────────────────────────────────────────

def _read_proc_modules() -> list[str]:
    """Return sorted list of currently loaded kernel module names."""
    try:
        with open("/proc/modules", "r") as f:
            return sorted(line.split()[0] for line in f if line.strip())
    except FileNotFoundError:
        log.warning("/proc/modules not found — not running on Linux?")
        return []
    except PermissionError:
        log.warning("Permission denied reading /proc/modules")
        return []


def _read_sysctl(key: str) -> str | None:
    """Read a sysctl value from /proc/sys (preferred) or `sysctl` command."""
    proc_path = "/proc/sys/" + key.replace(".", "/")
    try:
        with open(proc_path, "r") as f:
            return f.read().strip()
    except (FileNotFoundError, PermissionError):
        pass
    # Fallback to sysctl binary
    try:
        out = subprocess.run(
            ["sysctl", "-n", key],
            capture_output=True, text=True, timeout=5,
        )
        if out.returncode == 0:
            return out.stdout.strip()
    except FileNotFoundError:
        pass
    except Exception as exc:
        log.debug("sysctl fallback failed for %s: %s", key, exc)
    return None


def _read_sysctls(keys: list[str]) -> dict[str, str | None]:
    return {k: _read_sysctl(k) for k in keys}


def _sha256(path: str) -> str | None:
    """Return hex SHA-256 of a file, or None if inaccessible."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (FileNotFoundError, PermissionError):
        return None


def _hash_binaries(paths: list[str]) -> dict[str, str | None]:
    return {p: _sha256(p) for p in paths}


# ── Public API ───────────────────────────────────────────────────────────

def create_baseline(path: str | None = None) -> dict[str, Any]:
    """Snapshot current kernel state and save to JSON."""
    path = path or config.BASELINE_PATH
    baseline: dict[str, Any] = {
        "kernel_modules": _read_proc_modules(),
        "sysctls": _read_sysctls(config.MONITORED_SYSCTLS),
        "binary_hashes": _hash_binaries(config.TRUSTED_BINARIES),
    }
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(baseline, f, indent=2)
    log.info("Baseline saved to %s", path)
    return baseline


def load_baseline(path: str | None = None) -> dict[str, Any] | None:
    """Load baseline from JSON.  Returns None if file missing."""
    path = path or config.BASELINE_PATH
    if not os.path.isfile(path):
        log.warning("No baseline found at %s", path)
        return None
    with open(path, "r") as f:
        return json.load(f)


def compare_current_to_baseline(
    baseline: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Compare live system state against baseline.

    Returns a list of drift findings, each containing:
        drift_type, key, baseline_value, current_value, description
    """
    if baseline is None:
        baseline = load_baseline()
    if baseline is None:
        log.warning("Cannot compare — no baseline available")
        return []

    findings: list[dict[str, Any]] = []

    # ── Module diff ──────────────────────────────────────────────────
    bl_mods = set(baseline.get("kernel_modules", []))
    cur_mods = set(_read_proc_modules())
    for mod in sorted(cur_mods - bl_mods):
        findings.append({
            "drift_type": "new_module",
            "key": mod,
            "baseline_value": None,
            "current_value": mod,
            "description": f"New kernel module loaded: {mod}",
        })
    for mod in sorted(bl_mods - cur_mods):
        findings.append({
            "drift_type": "missing_module",
            "key": mod,
            "baseline_value": mod,
            "current_value": None,
            "description": f"Kernel module no longer loaded: {mod}",
        })

    # ── Sysctl diff ──────────────────────────────────────────────────
    bl_sysctl = baseline.get("sysctls", {})
    cur_sysctl = _read_sysctls(config.MONITORED_SYSCTLS)
    for key in config.MONITORED_SYSCTLS:
        bl_val = bl_sysctl.get(key)
        cur_val = cur_sysctl.get(key)
        if bl_val is not None and cur_val is not None and bl_val != cur_val:
            findings.append({
                "drift_type": "sysctl_drift",
                "key": key,
                "baseline_value": bl_val,
                "current_value": cur_val,
                "description": f"sysctl {key} changed: {bl_val} -> {cur_val}",
            })

    # ── Binary hash diff ────────────────────────────────────────────
    bl_hashes = baseline.get("binary_hashes", {})
    cur_hashes = _hash_binaries(config.TRUSTED_BINARIES)
    for path in config.TRUSTED_BINARIES:
        bl_h = bl_hashes.get(path)
        cur_h = cur_hashes.get(path)
        if bl_h and cur_h and bl_h != cur_h:
            findings.append({
                "drift_type": "binary_hash_drift",
                "key": path,
                "baseline_value": bl_h,
                "current_value": cur_h,
                "description": f"Hash changed for {path}",
            })

    return findings
