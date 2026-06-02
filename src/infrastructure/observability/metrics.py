"""Prometheus metrics integration - Honeypot SOC Edition"""
from prometheus_client import Counter, Histogram, Gauge, generate_latest, REGISTRY
from fastapi import Response
import time

# === Attacks Metrics ===
attacks_total = Counter(
    "honeypot_attacks_total",
    "Total attacks captured by protocol/type/severity",
    ["protocol", "type", "severity"]
)

attack_severity = Histogram(
    "honeypot_attack_severity_bucket",
    "Attack severity score distribution",
    buckets=[10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
)

attack_rate_per_minute = Gauge(
    "honeypot_attacks_rate_per_minute",
    "Attack rate calculated per minute window",
    ["window"]
)

# === Session Metrics ===
sessions_active = Gauge(
    "honeypot_sessions_active",
    "Currently active sessions"
)

sessions_total = Counter(
    "honeypot_sessions_total",
    "Total sessions created",
    ["protocol"]
)

session_duration = Histogram(
    "honeypot_session_duration_seconds",
    "Session duration distribution",
    buckets=[10, 30, 60, 120, 300, 600, 1800, 3600, float('inf')]
)

# === Attacker Metrics ===
attackers_total = Gauge(
    "honeypot_attackers_total",
    "Unique attacker IPs observed",
    ["threat_level"]
)

top_attackers = Gauge(
    "honeypot_top_attackers",
    "Top attacker IPs by attack count",
    ["attacker_ip", "country"]
)

# === Command Metrics ===
commands_logged = Counter(
    "honeypot_commands_total",
    "Total commands logged",
    ["flagged"]
)

# === IOC Metrics ===
iocs_total = Counter(
    "honeypot_iocs_total",
    "Indicators of Compromise extracted",
    ["ioc_type", "source"]
)

# === Payload Metrics ===
payload_size_bytes = Histogram(
    "honeypot_payload_size_bytes",
    "Payload size distribution",
    ["attack_type"],
    buckets=[64, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, float('inf')]
)

# === DB Metrics ===
db_queries = Counter(
    "honeypot_db_queries_total",
    "Database queries total",
    ["operation", "table"]
)

db_query_duration = Histogram(
    "honeypot_db_query_duration_seconds",
    "Database query duration",
    ["table", "operation"],
    buckets=[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0, float('inf')]
)

# === API Metrics ===
response_time = Histogram(
    "honeypot_response_time_seconds",
    "API endpoint response time",
    ["endpoint", "method"],
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, float('inf')]
)

api_requests = Counter(
    "honeypot_api_requests_total",
    "API requests by endpoint",
    ["endpoint", "method", "status"]
)

# === System Metrics ===
cowrie_events_processed = Counter(
    "honeypot_cowrie_events_processed",
    "Cowrie events processed by worker",
    ["event_type"]
)


def metrics_endpoint():
    """Expose Prometheus metrics endpoint"""
    return Response(
        content=generate_latest(REGISTRY),
        media_type="text/plain"
    )