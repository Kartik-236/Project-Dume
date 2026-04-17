#!/usr/bin/env bash
# ── Project DUME — Kali Launcher (Phase 2) ───────────────────────────────
# Usage:
#   ./scripts/run_kali.sh web       Start web mode via Docker Compose
#   ./scripts/run_kali.sh cli       CLI sanity check
#   ./scripts/run_kali.sh status    Show service status
#   ./scripts/run_kali.sh stop      Stop Docker Compose services
#   ./scripts/run_kali.sh logs      Tail app logs
#   ./scripts/run_kali.sh help      Show this usage
# ─────────────────────────────────────────────────────────────────────────
set -euo pipefail

# Resolve project root relative to this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
fail()  { echo -e "${RED}[-]${NC} $*"; }

# ── Check prerequisites ─────────────────────────────────────────────────
check_cmd() {
    if ! command -v "$1" &>/dev/null; then
        fail "Required command not found: $1"
        return 1
    fi
}

check_file() {
    if [ ! -f "$1" ]; then
        fail "Required file missing: $1"
        return 1
    fi
}

check_env() {
    local ok=true
    info "Checking prerequisites..."

    for cmd in python3 docker; do
        if check_cmd "$cmd"; then
            ok "$cmd: $(command -v "$cmd")"
        else
            ok=false
        fi
    done

    # docker compose (plugin or standalone)
    if docker compose version &>/dev/null; then
        ok "docker compose: $(docker compose version --short 2>/dev/null || echo 'available')"
    elif command -v docker-compose &>/dev/null; then
        ok "docker-compose: $(docker-compose --version)"
    else
        fail "docker compose not found"
        ok=false
    fi

    echo ""
    info "Versions:"
    python3 --version 2>/dev/null || true
    docker --version 2>/dev/null || true
    docker compose version 2>/dev/null || true

    echo ""
    info "Checking project files..."
    for f in Dockerfile docker-compose.yml app.py main.py requirements.txt; do
        if check_file "$f"; then
            ok "$f exists"
        else
            ok=false
        fi
    done

    if [ "$ok" = false ]; then
        fail "Some prerequisites are missing. Fix the issues above and retry."
        exit 1
    fi
    ok "All prerequisites satisfied"
    echo ""
}

# ── Ensure runtime directories ──────────────────────────────────────────
ensure_dirs() {
    mkdir -p baseline reporting/output storage
}

# ── Subcommands ──────────────────────────────────────────────────────────

cmd_web() {
    check_env
    ensure_dirs

    info "Building and starting services..."
    docker compose up --build -d

    info "Waiting for services to be ready..."
    local retries=30
    local ready=false
    for i in $(seq 1 $retries); do
        if curl -sf http://localhost:8000/api/status >/dev/null 2>&1; then
            ready=true
            break
        fi
        sleep 2
        echo -n "."
    done
    echo ""

    if [ "$ready" = true ]; then
        ok "Project DUME is running!"
        echo ""
        echo -e "  ${CYAN}Dashboard${NC}:  http://localhost:8000"
        echo -e "  ${CYAN}Health${NC}:     http://localhost:8000/health"
        echo -e "  ${CYAN}API Status${NC}: http://localhost:8000/api/status"
        echo ""
        echo "  Useful commands:"
        echo "    ./scripts/run_kali.sh status    Check service status"
        echo "    ./scripts/run_kali.sh logs      Tail app logs"
        echo "    ./scripts/run_kali.sh stop      Stop services"
        echo ""
        echo "  Quick test:"
        echo "    curl -X POST http://localhost:8000/api/run-baseline"
        echo "    curl -X POST http://localhost:8000/api/run-detection"
        echo ""
    else
        fail "App did not become healthy in time."
        warn "Check logs with:  docker compose logs app"
        warn "Check postgres:   docker compose logs postgres"
        exit 1
    fi
}

cmd_cli() {
    info "CLI mode — sanity check"
    echo ""

    local py="python3"
    if [ -f ".venv/bin/python" ]; then
        py=".venv/bin/python"
        info "Using virtualenv: $py"
    fi

    $py main.py --help

    echo ""
    info "CLI examples:"
    echo "  $py main.py --init-baseline --verbose"
    echo "  $py main.py --run-once --verbose"
    echo "  $py main.py --show-alerts"
}

cmd_status() {
    info "Docker Compose status:"
    docker compose ps 2>/dev/null || warn "No services running"
    echo ""

    info "Checking app health..."
    if curl -sf http://localhost:8000/api/status >/dev/null 2>&1; then
        ok "App is reachable at http://localhost:8000"
        curl -s http://localhost:8000/api/status | python3 -m json.tool 2>/dev/null || true
    else
        warn "App is not reachable at http://localhost:8000"
    fi
}

cmd_stop() {
    info "Stopping Docker Compose services..."
    docker compose down
    ok "Services stopped"
}

cmd_logs() {
    info "Tailing app logs (Ctrl+C to stop)..."
    docker compose logs -f app
}

cmd_help() {
    echo "Project DUME — Kali Launcher"
    echo ""
    echo "Usage: $0 <command>"
    echo ""
    echo "Commands:"
    echo "  web       Start Phase 2 web mode via Docker Compose"
    echo "  cli       Run local CLI sanity check"
    echo "  status    Show Docker/container/app health"
    echo "  stop      Stop Docker Compose services"
    echo "  logs      Tail app logs"
    echo "  help      Show this usage"
}

# ── Dispatch ─────────────────────────────────────────────────────────────

case "${1:-help}" in
    web)    cmd_web ;;
    cli)    cmd_cli ;;
    status) cmd_status ;;
    stop)   cmd_stop ;;
    logs)   cmd_logs ;;
    help)   cmd_help ;;
    *)      fail "Unknown command: $1"; cmd_help; exit 1 ;;
esac
