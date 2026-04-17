#!/usr/bin/env bash
# ── Project DUME — Quick Stop ────────────────────────────────────────────
# Convenience wrapper to stop Docker Compose services.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

echo "[*] Stopping Docker Compose services..."
docker compose down
echo "[+] Services stopped"
