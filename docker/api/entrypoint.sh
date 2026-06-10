#!/bin/bash
# API entrypoint
PORT=${API_PORT:-8000}

# GeoIP ready check (MMDB mounted or downloaded by host setup)
test -f /app/data/geolite2.mmdb && echo "GeoIP: MMDB available" || echo "GeoIP: using online fallback"

# Start API
echo "Starting API on port ${PORT}"
exec uvicorn app:app --host 0.0.0.0 --port ${PORT} --reload