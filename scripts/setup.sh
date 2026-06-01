#!/bin/bash
#
# Honeypot Setup Script - Local OCI Deployment
# Usage: ./setup.sh [--full] [--dry-run]
#
# Fetches secrets from GitHub and deploys Docker stack locally

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}✓${NC} $1"; }
log_warn() { echo -e "${YELLOW}⚠${NC} $1"; }
log_error() { echo -e "${RED}✗${NC} $1"; }

# Parse args
FULL_MODE=false
DRY_RUN=false
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --full) FULL_MODE=true ;;
        --dry-run) DRY_RUN=true ;;
        *) log_error "Unknown param: $1"; exit 1 ;;
    esac
    shift
done

echo "🍯 Honeypot Framework Setup"
echo ""

# Check gh CLI
if ! command -v gh &> /dev/null; then
    log_error "gh CLI not found. Install: https://cli.github.com"
    exit 1
fi

# Check if in repo
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    log_error "Not in a git repository"
    exit 1
fi

# Pull latest
if [ "$DRY_RUN" = false ]; then
    echo "[Git] Pulling latest changes..."
    git pull origin master --rebase 2>/dev/null || log_warn "Could not pull from git"
fi

# Create .env from template
if [ ! -f .env.example ]; then
    log_error ".env.example not found"
    exit 1
fi

echo "[Environment] Setting up .env..."
cp .env.example .env

# Fetch and inject secrets from GitHub
# Note: Requires gh auth login and repo access
fetch_secret() {
    local secret_name=$1
    if gh secret list 2>/dev/null | grep -q "$secret_name"; then
        local value=$(gh api repos/damo-pmu/honeypot/actions/secrets/$secret_name 2>/dev/null || echo "")
        if [ -n "$value" ]; then
            sed -i "s/^${secret_name}=/${secret_name}=${value}/" .env
            log_info "Injected $secret_name from GitHub secrets"
        fi
    else
        log_warn "$secret_name not found in repo secrets, using default"
    fi
}

# Try to inject secrets (will use defaults if not available)
fetch_secret "API_KEY_OPENROUTER"
fetch_secret "DASHBOARD_PASSWORD" 
fetch_secret "PG_PASS"
fetch_secret "GRAFANA_PASSWORD"

# Docker setup
echo ""
echo "[Docker] Building images..."
docker compose build --no-cache

echo ""
echo "[Docker] Starting services..."
if [ "$FULL_MODE" = true ]; then
    docker compose --profile full up -d
else
    docker compose up -d api postgres redis cowrie worker
fi

echo ""
log_info "Setup complete!"
echo ""
echo "Endpoints:"
echo "  API:         http://localhost:${API_PORT:-8000}"
echo "  Dashboard:   http://localhost:${API_PORT:-8000}/dashboard/"
echo "  Cowrie SSH:  localhost:${SSH_PORT:-22}"
echo "  Grafana:     http://localhost:${GRAFANA_PORT:-3000} (use --full)"
echo ""
echo "Dashboard password: ${DASHBOARD_PASSWORD:-demo} (check .env)"