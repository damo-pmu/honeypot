# Worker Dockerfile - reads Cowrie JSON logs and publishes to RabbitMQ
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY src/workers/cowrie_producer.py .

CMD ["python", "cowrie_producer.py"]