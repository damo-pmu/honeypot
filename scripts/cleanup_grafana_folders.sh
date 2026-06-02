#!/bin/bash
# Delete existing Honeypot folders to allow clean re-provisioning

GRAFANA_URL="${GRAFANA_URL:-http://localhost:3000}"
GRAFANA_PASS="${GRAFANA_PASS:-demo}"

# Get folder IDs and delete them
for folder in "honeypot-monitoring" "honeypot-investigation"; do
  FOLDER_INFO=$(curl -s -u admin:${GRAFANA_PASS} "${GRAFANA_URL}/api/folders/${folder}" 2>/dev/null)
  if [ -n "$FOLDER_INFO" ]; then
    FOLDER_ID=$(echo "$FOLDER_INFO" | jq -r '.id' 2>/dev/null)
    if [ "$FOLDER_ID" != "null" ]; then
      echo "Deleting folder ${folder} (ID: ${FOLDER_ID})"
      curl -s -X DELETE -u admin:${GRAFANA_PASS} "${GRAFANA_URL}/api/folders/${FOLDER_ID}" 2>/dev/null
    fi
  fi
done

echo "Cleanup done"