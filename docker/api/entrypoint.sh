#!/bin/bash
# API entrypoint - uses environment variables for port configuration

# Default port if not set
PORT=${API_PORT:-8000}

echo "Starting API on port ${PORT}"
exec uvicorn app:app --host 0.0.0.0 --port ${PORT}