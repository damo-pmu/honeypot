#!/bin/bash
set -e

echo "══════════════════════════════════════════════"
echo "🌐 Honeypot Tor Seed - Realistic Attack Testing"
echo "══════════════════════════════════════════════"

# Get public IP if not set
if [ -z "$PUBLIC_IP" ]; then
    PUBLIC_IP=$(curl -s https://api.ipify.org 2>/dev/null || echo "unknown")
    echo "Detected public IP: $PUBLIC_IP"
    export PUBLIC_IP
fi

# Start seed worker in background
docker-compose run -d --name seed-worker \
    --build \
    tor \
    seed-worker

echo "Seed worker started - generating Tor attacks every $SEED_INTERVAL seconds"
echo "Monitor with: docker-compose logs -f seed-worker"