# Cowrie honeypot integration - Docker setup
# Uses official cowrie image with volume mount for config/logs

FROM cowrie/cowrie:latest

# No custom config needed - official image works with defaults
# Logs go to /cowrie/var/log/cowrie.json by default

EXPOSE 2222 23

# Health check
HEALTHCHECK --interval=30s --timeout=3s CMD nc -z localhost 2222 || exit 1