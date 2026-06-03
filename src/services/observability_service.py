"""Observability Service - Prometheus metrics and OpenTelemetry tracing"""
import os
from typing import Optional

# Try optional imports
try:
    from prometheus_client import Counter, Histogram, Gauge, generate_latest
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False

try:
    from opentelemetry import trace, metrics
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.metrics import MeterProvider
    OTEL_AVAILABLE = True
except ImportError:
    OTEL_AVAILABLE = False


# Metrics definitions
if PROMETHEUS_AVAILABLE:
    events_ingested = Counter('honeypot_events_ingested_total', 'Total events ingested')
    payload_analyzed = Counter('honeypot_payloads_analyzed_total', 'Total payloads analyzed')
    threats_detected = Counter('honeypot_threats_detected_total', 'Total threats detected', ['type'])
    db_queries = Histogram('honeypot_db_query_seconds', 'Database query latency')
    sse_messages = Counter('honeypot_sse_messages_total', 'SSE messages sent')
    api_latency = Histogram('honeypot_api_seconds', 'API endpoint latency', ['endpoint'])


class ObservabilityService:
    """
    Metrics collection for SOC operations.
    
    - Prometheus: /metrics endpoint
    - OpenTelemetry: distributed tracing
    - Status: ingestion_rate, processing_latency, sse_latency, api_latency, db_latency
    """
    
    def __init__(self):
        if OTEL_AVAILABLE:
            self._init_tracing()
    
    def _init_tracing(self):
        """Initialize OpenTelemetry tracer"""
        resource = Resource.create({"service.name": "honeypot-platform"})
        provider = TracerProvider(resource=resource)
        trace.set_tracer_provider(provider)
        self.tracer = trace.get_tracer(__name__)
    
    def record_ingestion(self, count: int = 1):
        """Record event ingestion"""
        if PROMETHEUS_AVAILABLE:
            events_ingested.inc(count)
    
    def record_payload_analysis(self, count: int = 1):
        """Record payload analysis"""
        if PROMETHEUS_AVAILABLE:
            payload_analyzed.inc(count)
    
    def record_threat(self, threat_type: str):
        """Record threat detection"""
        if PROMETHEUS_AVAILABLE:
            threats_detected.labels(type=threat_type).inc()
    
    def get_metrics(self) -> Optional[bytes]:
        """Get Prometheus metrics output"""
        if PROMETHEUS_AVAILABLE:
            return generate_latest()
        return None
    
    def start_span(self, name: str, attributes: dict = None):
        """Start OpenTelemetry span"""
        if OTEL_AVAILABLE and attributes:
            with self.tracer.start_as_current_span(name) as span:
                for k, v in attributes.items():
                    span.set_attribute(k, v)


# Singleton
observability = ObservabilityService()