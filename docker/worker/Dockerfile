# Worker Dockerfile - reads Cowrie JSON logs and pushes to API
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/workers/cowrie_ingest.py .

CMD ["python", "cowrie_ingest.py"]