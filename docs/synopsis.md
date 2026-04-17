# Project DUME — Synopsis

**Official Title:** Secure Kernel Linux Hardening Against Rootkits and Privilege Escalation

## Problem Statement

Modern Linux systems remain vulnerable to kernel-level attacks — rootkit module injection, privilege escalation via SUID binaries, and runtime weakening of kernel security parameters. Traditional host security tools focus on user-space threats and often miss kernel integrity drift until it is too late.

## Objective

Project DUME implements a lightweight, modular, kernel-aware host security framework that:

1. Establishes a **trusted baseline** of kernel modules, security-relevant sysctl values, and privileged binary hashes.
2. Continuously **collects runtime telemetry** from Linux-native sources (`/proc`, `dmesg`, `journalctl`, audit logs).
3. **Normalises** heterogeneous events into a common schema for analysis.
4. **Detects** kernel integrity drift (new/suspicious modules, sysctl weakening, binary tampering, deleted executables) and privilege escalation indicators (abnormal root execution, suspicious command usage, dangerous capabilities).
5. **Correlates** findings using weighted risk scoring with pattern bonuses and generates actionable alerts.
6. Provides a **web dashboard** for visual monitoring, experiment tracking, and research paper screenshots.

## Approach

The framework follows a sequential pipeline architecture — baseline, collect, normalise, detect, correlate, report — implemented as a modular Python project. Phase 2 adds a FastAPI web dashboard, PostgreSQL persistence, structured run/finding storage, and enhanced detection (deleted-exe, capability checks, expanded correlation).

## Scope

This is an academic working model (Phase 2) for safe lab testing and research. It prioritises correctness, modularity, and demonstrability. Advanced features (live eBPF probes, daemon mode, automated response) are documented as future extensions.
