# Cowrie honeypot integration - Docker setup
# Uses official cowrie image with custom config

FROM cowhi/cowrie:latest

# Expose SSH and Telnet ports
EXPOSE 2222 23

# Copy custom cowrie.cfg
COPY cowrie.cfg /cowrie/cowrie.cfg

# Health check
HEALTHCHECK --interval=30s --timeout=3s \
    CMD nc -z localhost 2222 || exit 1