"""
Project DUME — eBPF Collector (Stub)

This module is a placeholder for future eBPF-based telemetry collection.
No eBPF libraries are imported or required for the MVP.

TODO — Future extension goals:
  - Attach eBPF probes to kernel tracepoints (e.g. sys_enter_execve,
    sys_enter_finit_module) for real-time visibility into privilege
    escalation and module loading at the kernel level.
  - Consider using bcc or bpftrace Python bindings.
  - eBPF requires a Linux ≥4.15 kernel with CONFIG_BPF, CAP_SYS_ADMIN,
    and typically root access.
  - Inside Docker, eBPF access requires --privileged or explicit
    cap-add=SYS_ADMIN plus mounted /sys/kernel/debug.
"""

import logging
from typing import Any

log = logging.getLogger("dume.collectors.ebpf")


def collect_ebpf_events() -> list[dict[str, Any]]:
    """Placeholder — always returns an empty list in the MVP.

    Future implementation would attach eBPF probes and stream events
    through a ring-buffer or perf map back to this collector.
    """
    log.debug("eBPF collector is a stub — no events collected")
    return []
