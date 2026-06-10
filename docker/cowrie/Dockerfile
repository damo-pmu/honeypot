# Debian-based Cowrie for flexible logging control
FROM debian:bookworm-slim

# Dependencies
RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-venv \
    libffi-dev libssl-dev netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Install Cowrie via pip (latest stable)
WORKDIR /cowrie
RUN python3 -m venv cowrie-env && \
    /cowrie/cowrie-env/bin/pip install --no-cache-dir cowrie

# Create cowrie user (non-root as required)
RUN useradd -m -s /bin/bash cowrie

# Copy config with JSON logging enabled
COPY cowrie.cfg /cowrie/cowrie-git/etc/cowrie.cfg
COPY userdb.txt /cowrie/cowrie-git/etc/userdb.txt

# Copy userdb to pip package location (where Cowrie looks for it)
RUN mkdir -p /cowrie/cowrie-env/lib/python3.11/site-packages/cowrie/data/etc
COPY userdb.txt /cowrie/cowrie-env/lib/python3.11/site-packages/cowrie/data/etc/userdb.txt

# Create log/lib directories with proper permissions for cowrie user
# Cowrie pip package creates var/log/cowrie/ and var/lib/cowrie/ relative to WORKDIR
RUN mkdir -p /cowrie/var/log/cowrie /cowrie/var/lib/cowrie/tty && \
    chown -R cowrie:cowrie /cowrie && \
    chmod -R 755 /cowrie

# Volumes - MUST match worker mount
VOLUME ["/cowrie/var/log/cowrie", "/cowrie/var/lib/cowrie"]

EXPOSE 2222 23

# Run as cowrie user (required by Cowrie security)
USER cowrie

# Health check
HEALTHCHECK --interval=30s --timeout=3s CMD nc -z localhost 2222 || exit 1

ENTRYPOINT ["/cowrie/cowrie-env/bin/twistd", "-n", "--umask=0022", "--pidfile=", "cowrie"]