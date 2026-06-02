"""Prometheus metrics integration"""
from prometheus_client import Counter, Histogram, Gauge, generate_latest
from fastapi import Response

# Metrics definitions
attacks_total = Counter(
    "honeypot_attacks_total",
    "Total attacks captured",
    ["protocol", "type", "severity"]
)

sessions_active = Gauge(
    "honeypot_sessions_active",
    "Currently active sessions"
)

attack_severity = Histogram(
    "honeypot_attack_severity",
    "Attack severity distribution",
    buckets=[10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
)

response_time = Histogram(
    "honeypot_response_time_seconds",
    "API response time"
)

# DB query metrics
db_queries = Counter(
    "honeypot_db_queries_total",
    "Total database queries",
    ["operation", "table"]
)

# IOC metrics
iocs_total = Counter(
    "honeypot_iocs_total",
    "Indicators of Compromise extracted",
    ["ioc_type"]
)

commands_logged = Counter(
    "honeypot_commands_total",
    "Commands logged",
    ["flagged"]
)


def metrics_endpoint():
    """Expose Prometheus metrics"""
    return Response(
        content=generate_latest(),
        media_type="text/plain"
    )