"""
Project DUME — Main Pipeline Orchestrator

Usage:
    python main.py --init-baseline          Create / update trusted baseline
    python main.py --run-once               Run one full detection cycle
    python main.py --run-once --verbose      … with debug-level output
    python main.py --show-alerts            Print recent alerts from DB
"""

import argparse
import logging
import sys
from typing import Any

import config
from baseline.baseline_manager import (
    compare_current_to_baseline,
    create_baseline,
    load_baseline,
)
from collectors.audit_collector import collect_audit_events
from collectors.dmesg_collector import collect_dmesg_events
from collectors.journal_collector import collect_journal_events
from collectors.proc_collector import collect_process_events
from correlation.correlator import correlate
from detection.integrity_detector import analyse as integrity_analyse
from detection.privilege_detector import analyse as privilege_analyse
from normalization.normalizer import normalize_events
from reporting.reporter import (
    generate_incident_summary,
    print_alert_to_console,
    save_alert_json,
)
from storage.event_store import (
    fetch_recent_alerts,
    init_db,
    save_alert,
    save_events,
)

log = logging.getLogger("dume")


# ── CLI ──────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="project-dume",
        description="Project DUME — Kernel-Aware Host Security Framework",
    )
    p.add_argument("--init-baseline", action="store_true",
                   help="Create or update the trusted baseline snapshot")
    p.add_argument("--run-once", action="store_true",
                   help="Run a single detection cycle")
    p.add_argument("--show-alerts", action="store_true",
                   help="Show recent alerts stored in the database")
    p.add_argument("--verbose", "-v", action="store_true",
                   help="Enable debug-level logging")
    return p


# ── Pipeline steps ───────────────────────────────────────────────────────

def do_init_baseline() -> None:
    print("[*] Creating / updating baseline …")
    bl = create_baseline()
    mods = len(bl.get("kernel_modules", []))
    sysctls = len(bl.get("sysctls", {}))
    bins = sum(1 for v in bl.get("binary_hashes", {}).values() if v)
    print(f"[+] Baseline saved: {mods} modules, {sysctls} sysctls, {bins} binary hashes")
    print(f"    Path: {config.BASELINE_PATH}")


def do_run_once() -> None:
    # 1. Database
    init_db(config.DB_PATH)

    # 2. Baseline
    baseline = load_baseline()
    if baseline is None:
        print("[!] No baseline found. Creating one now …")
        print("    Re-run with --run-once after baseline is established for")
        print("    meaningful drift detection.")
        create_baseline()
        baseline = load_baseline()

    # 3. Collect telemetry
    print("[*] Collecting telemetry …")
    raw_events: list[dict[str, Any]] = []
    raw_events.extend(collect_process_events())
    raw_events.extend(collect_dmesg_events())
    raw_events.extend(collect_journal_events())
    raw_events.extend(collect_audit_events())

    print(f"    Raw events collected: {len(raw_events)}")

    # 4. Normalize
    normalized = normalize_events(raw_events)
    print(f"    Normalized events  : {len(normalized)}")

    # 5. Persist events
    saved = save_events(config.DB_PATH, normalized)
    log.debug("Saved %d events to DB", saved)

    # 6. Baseline comparison
    print("[*] Comparing against baseline …")
    drift = compare_current_to_baseline(baseline)
    if drift:
        print(f"    Baseline drift items: {len(drift)}")
    else:
        print("    No baseline drift detected.")

    # 7. Detection
    print("[*] Running detectors …")
    integrity_findings = integrity_analyse(drift, normalized)
    privilege_findings = privilege_analyse(normalized)
    all_findings = integrity_findings + privilege_findings
    print(f"    Integrity findings : {len(integrity_findings)}")
    print(f"    Privilege findings : {len(privilege_findings)}")

    # 8. Correlation
    alert = correlate(all_findings)
    score = alert["total_score"]
    severity = alert["severity"]
    print(f"    Total risk score   : {score} ({severity})")

    # 9. Alert / report
    if score >= config.ALERT_THRESHOLD:
        print_alert_to_console(alert)
        save_alert(config.DB_PATH, alert)
        path = save_alert_json(alert)
        print(f"[+] Alert persisted to DB and saved to {path}")
        summary = generate_incident_summary(alert)
        log.debug("Incident summary:\n%s", summary)
    else:
        print("[+] Score below alert threshold — system looks nominal.")

    print("[*] Detection cycle complete.")


def do_show_alerts() -> None:
    init_db(config.DB_PATH)
    alerts = fetch_recent_alerts(config.DB_PATH, limit=10)
    if not alerts:
        print("[i] No alerts stored yet.")
        return
    for i, a in enumerate(alerts, 1):
        sev = a.get("severity", "?").upper()
        score = a.get("total_score", 0)
        ts = a.get("timestamp", "?")
        n = len(a.get("findings", []))
        print(f"  {i}. [{sev}] score={score}  findings={n}  time={ts}")
        print(f"     {a.get('summary', '')[:120]}")


# ── Entrypoint ───────────────────────────────────────────────────────────

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    ran_something = False

    if args.init_baseline:
        do_init_baseline()
        ran_something = True

    if args.run_once:
        do_run_once()
        ran_something = True

    if args.show_alerts:
        do_show_alerts()
        ran_something = True

    if not ran_something:
        parser.print_help()
        print("\nHint: try  python main.py --run-once --verbose")


if __name__ == "__main__":
    main()
