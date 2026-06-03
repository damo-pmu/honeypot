# Cowrie honeypot integration - Docker setup
# Uses official cowrie image with custom config

FROM cowrie/cowrie:latest

# Copy config to the CORRECT location (Cowrie loads from /cowrie/cowrie-git/etc/)
COPY cowrie.cfg /cowrie/cowrie-git/etc/cowrie.cfg

EXPOSE 2222 23

# Health check
HEALTHCHECK --interval=30s --timeout=3s CMD nc -z localhost 2222 || exit 1
    CMD nc -z localhost 2222 || exit 1