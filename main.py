"""
Project DUME — Main Pipeline Orchestrator (Phase 2)

CLI interface preserved from Phase 1.
Now uses services.pipeline_service internally for shared logic.

Usage:
    python main.py --init-baseline          Create / update trusted baseline
    python main.py --run-once               Run one full detection cycle
    python main.py --run-once --verbose      ... with debug-level output
    python main.py --show-alerts            Print recent alerts from DB
"""

import argparse
import logging

import config
from services.pipeline_service import run_baseline, run_detection_cycle
from storage.event_store import fetch_recent_alerts, init_db

log = logging.getLogger("dume")


# ── CLI ──────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="project-dume",
        description="Project DUME -- Kernel-Aware Host Security Framework",
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
    print("[*] Creating / updating baseline ...")
    result = run_baseline()
    print(f"[+] {result['message']}")
    print(f"    Path: {result['path']}")


def do_run_once() -> None:
    init_db()

    print("[*] Collecting telemetry ...")
    result = run_detection_cycle()

    print(f"    Raw events collected: {result['raw_events_count']}")
    print(f"    Normalized events  : {result['normalized_events_count']}")

    drift = result['integrity_findings_count']
    print(f"[*] Comparing against baseline ...")
    if drift:
        print(f"    Integrity findings : {drift}")
    else:
        print("    No baseline drift detected.")

    print("[*] Running detectors ...")
    print(f"    Integrity findings : {result['integrity_findings_count']}")
    print(f"    Privilege findings : {result['privilege_findings_count']}")
    print(f"    Total risk score   : {result['total_score']} ({result['severity']})")

    if result.get('alert_saved'):
        from reporting.reporter import print_alert_to_console, generate_incident_summary
        # Reconstruct minimal alert for console display
        alert = {
            "severity": result["severity"],
            "total_score": result["total_score"],
            "timestamp": result["timestamp"],
            "summary": result["summary"],
            "recommended_action": result["recommended_action"],
            "findings": result.get("findings", []),
        }
        print_alert_to_console(alert)
        print(f"[+] Alert persisted to DB and saved to {result.get('report_path')}")
    else:
        print("[+] Score below alert threshold -- system looks nominal.")

    print("[*] Detection cycle complete.")


def do_show_alerts() -> None:
    init_db()
    alerts = fetch_recent_alerts(limit=10)
    if not alerts:
        print("[i] No alerts stored yet.")
        return
    for i, a in enumerate(alerts, 1):
        sev = a.get("severity", "?").upper()
        score = a.get("total_score", 0)
        ts = a.get("timestamp", "?")
        print(f"  {i}. [{sev}] score={score}  time={ts}")
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
