#!/bin/bash
set -e

# Idempotent GeoIP MMDB setup
MMDB_DIR="/app/data"
MMDB_FILE="$MMDB_DIR/geolite2.mmdb"
MMDB_URL="https://github.com/P3TER/mmdb/raw/main/GeoLite2-City.mmdb"

mkdir -p "$MMDB_DIR"

# Download if missing or older than 7 days
if [ ! -f "$MMDB_FILE" ] || [ $(find "$MMDB_FILE" -mtime +7 2>/dev/null | wc -l) -gt 0 ]; then
    echo "Downloading GeoLite2-City.mmdb..."
    curl -sL "$MMDB_URL" -o "$MMDB_FILE.tmp" || wget -q "$MMDB_URL" -O "$MMDB_FILE.tmp"
    mv "$MMDB_FILE.tmp" "$MMDB_FILE" 2>/dev/null || true
    chmod 644 "$MMDB_FILE"
    echo "GeoIP database ready: $(du -h "$MMDB_FILE" | cut -f1)"
fi

# Verify
if [ -f "$MMDB_FILE" ]; then
    echo "GeoIP ready at $MMDB_FILE"
else
    echo "Warning: GeoIP database not available, will use online fallback"
fi

exec "$@"