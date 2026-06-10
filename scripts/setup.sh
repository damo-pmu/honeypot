#!/bin/bash
set -e

echo "══════════════════════════════════════════════"
echo "🛡️  Honeypot GeoIP - Setup Production"
echo "══════════════════════════════════════════════"

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$DIR")"
cd "$PROJECT_ROOT"

# Step 1: Environment - GitHub secrets fallback
echo "[1/4] Environment check..."
test -f .env || cp .env.example .env

# Set PUBLIC_IP from GitHub secrets or auto-detect
if [ -z "$(grep '^PUBLIC_IP=' .env 2>/dev/null | cut -d= -f2)" ] && [ -z "$PUBLIC_IP" ]; then
    PUBLIC_IP=$(curl -s https://api.ipify.org 2>/dev/null || echo "")
    if [ -n "$PUBLIC_IP" ]; then
        echo "Detected PUBLIC_IP: $PUBLIC_IP"
        sed -i "s/^PUBLIC_IP=.*$/PUBLIC_IP=$PUBLIC_IP/" .env 2>/dev/null || echo "PUBLIC_IP=$PUBLIC_IP" >> .env
    fi
fi

# Step 2: GeoIP Database
echo "[2/4] GeoIP setup..."
bash "$DIR/setup-geoip.sh"

# Step 3: Database initialization
echo "[3/4] Database schema..."
if command -v docker &> /dev/null; then
    docker-compose up -d postgres redis rabbitmq
    sleep 8
    if [ -d "migrations" ]; then
        for f in migrations/*.sql; do
            [ -f "$f" ] && docker exec -i honeypot_postgres psql -U honeypot honeypot < "$f" 2>/dev/null || true
        done
    fi
else
    python3 "$DIR/db_maintenance.py" --init 2>/dev/null || true
fi

# Step 4: Build and start all services
echo "[4/4] Starting services..."
if command -v docker &> /dev/null; then
    docker-compose up -d --build
    echo "✅ Services started"
    echo "   Dashboard: http://localhost:8000/dashboard/map"
    echo "   API Health: http://localhost:8000/health"
else
    echo "Docker not available"
fi

# Verify
sleep 3
curl -sf http://localhost:8000/health > /dev/null && echo "✅ API OK" || echo "⚠️ API not responding"