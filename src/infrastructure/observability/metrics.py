"""Prometheus metrics integration"""
from prometheus_client import Counter, Histogram, Gauge, generate_latest
from fastapi import Response

# Metrics definitions
attacks_total = Counter(
    "honeypot_attacks_total",
    "Total attacks captured",
    ["protocol", "type"]
)

sessions_active = Gauge(
    "honeypot_sessions_active",
    "Currently active sessions"
)

attack_severity = Histogram(
    "honeypot_attack_severity",
    "Attack severity distribution",
    buckets=[10, 20, 30, 40, 50, 100]
)

response_time = Histogram(
    "honeypot_response_time_seconds",
    "API response time"
)

def metrics_endpoint():
    """Expose Prometheus metrics"""
    return Response(
        content=generate_latest(),
        media_type="text/plain"
    )