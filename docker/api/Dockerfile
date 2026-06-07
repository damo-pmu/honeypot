FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir "starlette>=0.27.0,<1.0" && \
    pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY src/ ./src/
COPY src/static/ /app/static/
COPY src/templates/ /app/templates/
COPY app.py .
COPY docker/api/entrypoint.sh /entrypoint.sh
COPY scripts/ /app/scripts/
RUN chmod +x /entrypoint.sh

EXPOSE 8000

ENTRYPOINT ["/entrypoint.sh"]