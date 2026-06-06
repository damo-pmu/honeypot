#!/bin/bash
#
# Honeypot Setup Script - Local OCI Deployment
# Usage: ./setup.sh [--full] [--dry-run]
#
# Fetches variables from GitHub and deploys Docker stack locally
#

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

# Try to fetch variables from GitHub
declare -A GH_VARS
# Include CORS and hostname so they can be provided from GH variables when available
VARS=("API_KEY_OPENROUTER" "PG_PASS" "GRAFANA_PASS" "DASHBOARD_PASS" "CORS_ALLOWED_ORIGINS" "HONEYPOT_HOSTNAME")
FETCHED_VARS=()

for var in "${VARS[@]}"; do
    # Query GH variables; if gh CLI not authenticated this will silently fail
    value=$(gh variable list --json name,value --jq ".[] | select(.name == \"$var\").value" 2>/dev/null || echo "")
    if [ -n "$value" ]; then
        GH_VARS[$var]="$value"
        FETCHED_VARS+=("$var")
        log_info "Fetched variable: $var"
    else
        log_warn "Variable $var not found on GitHub (using defaults)"
    fi
done

# Check if .env.local exists for overrides
if [ -f .env.local ]; then
    log_info "Using .env.local for overrides"
else
    # Build .env with fetched variables
    cp .env.example .env
    
    # Inject fetched variables
    for var in "${FETCHED_VARS[@]}"; do
        # Map to correct .env key names (must match .env.example)
        case $var in
            API_KEY_OPENROUTER) env_key="OPENROUTER_API_KEY" ;;
            PG_PASS) env_key="PG_PASS" ;;
            GRAFANA_PASS) env_key="GRAFANA_PASS" ;;
            DASHBOARD_PASS) env_key="DASHBOARD_PASS" ;;
            CORS_ALLOWED_ORIGINS) env_key="CORS_ALLOWED_ORIGINS" ;;
            HONEYPOT_HOSTNAME) env_key="HONEYPOT_HOSTNAME" ;;
            *) env_key="$var" ;;
        esac

        # Update .env with fetched value if key exists in template
        if grep -q "^$env_key=" .env 2>/dev/null; then
            # Escape slashes to avoid sed issues
            safe_value=$(printf '%s' "${GH_VARS[$var]}" | sed 's|\\|\\\\|g; s|/|\\/|g')
            sed -i "s|^$env_key=.*|$env_key=$safe_value|" .env
            log_info "Updated $env_key in .env"
        else
            # Append unknown keys to .env for completeness
            echo "$env_key=${GH_VARS[$var]}" >> .env
            log_info "Appended $env_key to .env"
        fi
    done
fi

# Docker setup
echo ""
echo "[Docker] Building images..."
docker compose build --no-cache

echo ""
echo "[Docker] Starting services..."
# Import dashboard via API
import_dashboard() {
    echo "[Grafana] Importing dashboards..."
    sleep 5  # Wait for Grafana to be ready
    
    GRAFANA_PASS="${GRAFANA_PASS:-demo}"
    if [ -f .env ]; then
        GRAFANA_PASS=$(grep '^GRAFANA_PASS=' .env | cut -d'=' -f2 || echo "demo")
    fi
    
    local grafana_host="localhost"
    if [ -f .env ]; then
        grafana_host=$(grep '^HONEYPOT_HOSTNAME=' .env | cut -d'=' -f2 || echo "localhost")
    fi

    # Import monitoring dashboard
    curl -s -u "admin:${GRAFANA_PASS}" \
        -X POST "http://${grafana_host}:3000/api/dashboards/db" \
        -H 'Content-Type: application/json' \
        -d @grafana/dashboard-monitoring.json > /dev/null 2>&1 && log_info "Monitoring dashboard imported" || log_warn "Monitoring dashboard import failed"
    
    # Import investigation dashboard  
    curl -s -u "admin:${GRAFANA_PASS}" \
        -X POST "http://${grafana_host}:3000/api/dashboards/db" \
        -H 'Content-Type: application/json' \
        -d @grafana/dashboard-investigation.json > /dev/null 2>&1 && log_info "Investigation dashboard imported" || log_warn "Investigation dashboard import failed"
}

echo ""
if [ "$FULL_MODE" = true ]; then
    docker compose --profile full up -d
else
    docker compose up -d api postgres redis cowrie worker maintenance
fi

# Import dashboard after full mode
if [ "$FULL_MODE" = true ] && [ "$DRY_RUN" = false ]; then
    import_dashboard
fi

echo ""
log_info "Setup complete!"
echo ""
if [ -f .env ]; then
    HONEYPOT_HOSTNAME=$(grep '^HONEYPOT_HOSTNAME=' .env | cut -d'=' -f2 || echo "localhost")
else
    HONEYPOT_HOSTNAME=localhost
fi

echo "Endpoints:"
echo "  API:         http://${HONEYPOT_HOSTNAME}:${API_PORT:-8000}"
echo "  Dashboard:   http://${HONEYPOT_HOSTNAME}:${API_PORT:-8000}/dashboard/"
echo "  Cowrie SSH:  ${HONEYPOT_HOSTNAME}:${SSH_PORT:-22}"
echo "  Grafana:     http://${HONEYPOT_HOSTNAME}:${GRAFANA_PORT:-3000} (use --full)"
echo ""
echo "Dashboard password: ${DASHBOARD_PASS:-demo} (check .env)"