#!/bin/bash
# Import dashboard via Grafana API
GRAFANA_URL="http://localhost:3000"
GRAFANA_USER="admin"
GRAFANA_PASS="${GRAFANA_PASS:-demo}"

# Import dashboard
curl -s -u "${GRAFANA_USER}:${GRAFANA_PASS}" \
  -X POST "${GRAFANA_URL}/api/dashboards/db" \
  -H 'Content-Type: application/json' \
  -d @/home/ubuntu/test-honeypot/grafana/dashboard.json | jq .