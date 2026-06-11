FROM python:3.11-slim
WORKDIR /app
COPY src/ ./src/
COPY scripts/seed_worker_pro.py ./
RUN pip install --no-cache-dir aiohttp pyyaml asyncssh
ENTRYPOINT ["python", "seed_worker_pro.py"]