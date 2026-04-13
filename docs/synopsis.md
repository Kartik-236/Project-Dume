# Project DUME — Synopsis

**Official Title:** Secure Kernel Linux Hardening Against Rootkits and Privilege Escalation

## Problem Statement

Modern Linux systems remain vulnerable to kernel-level attacks — rootkit module injection, privilege escalation via SUID binaries, and runtime weakening of kernel security parameters. Traditional host security tools focus on user-space threats and often miss kernel integrity drift until it is too late.

## Objective

Project DUME implements a lightweight, modular, kernel-aware host security framework that:

1. Establishes a **trusted baseline** of kernel modules, security-relevant sysctl values, and privileged binary hashes.
2. Continuously **collects runtime telemetry** from Linux-native sources (`/proc`, `dmesg`, `journalctl`, audit logs).
3. **Normalises** heterogeneous events into a common schema for analysis.
4. **Detects** kernel integrity drift (new/suspicious modules, sysctl weakening, binary tampering) and privilege escalation indicators (abnormal root execution, suspicious command usage).
5. **Correlates** findings using weighted risk scoring and generates actionable alerts.

## Approach

The framework follows a sequential pipeline architecture — baseline → collect → normalise → detect → correlate → report — and is implemented as a pure-Python project with a single external dependency (`psutil`). It supports Dockerised execution for portable deployment on Kali, Ubuntu, or any Linux host.

## Scope

This is an academic MVP / seminar-capstone prototype. It prioritises correctness, modularity, and demonstrability over production-grade completeness. Advanced features such as live eBPF probes, continuous daemon mode, and automated response actions are documented as future extensions.
