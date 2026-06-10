FROM python:3.11-slim
WORKDIR /app
COPY src/ ./src/
COPY scripts/seed_attacks.py .
RUN pip install --no-cache-dir aiohttp pyyaml
ENTRYPOINT ["python", "seed_attacks.py"]