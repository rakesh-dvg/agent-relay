"""Structured JSON logging and optional OpenTelemetry for Agent Relay."""

from __future__ import annotations

import contextlib
import json
import logging
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Any

REQUEST_ID_HEADER = "X-Request-ID"
REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
SERVICE_NAME = "agent-relay"

_LOGGING_CONFIGURED = False
_TELEMETRY_CONFIGURED = False

EXTRA_LOG_FIELDS = {
    "service_name": "service.name",
    "request_id": "request_id",
    "trace_id": "trace_id",
    "http_method": "http.method",
    "http_route": "http.route",
    "http_status_code": "http.status_code",
    "duration_ms": "duration_ms",
    "error_count": "error_count",
}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
            "level": record.levelname,
            "service.name": SERVICE_NAME,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for attr, field in EXTRA_LOG_FIELDS.items():
            value = getattr(record, attr, None)
            if value is not None:
                payload[field] = value
        if record.exc_info and record.levelno >= logging.ERROR:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=True)


def telemetry_enabled() -> bool:
    return os.getenv("OTEL_SDK_DISABLED", "").lower() not in ("true", "1", "yes")


def resolve_request_id(header_value: str | None) -> str:
    if header_value:
        candidate = header_value.strip()
        if REQUEST_ID_PATTERN.fullmatch(candidate):
            return candidate
    return str(uuid.uuid4())


def current_trace_id() -> str | None:
    if not telemetry_enabled():
        return None
    try:
        from opentelemetry import trace

        span_context = trace.get_current_span().get_span_context()
        if span_context.is_valid:
            return format(span_context.trace_id, "032x")
    except Exception:
        return None
    return None


def configure_logging() -> None:
    global _LOGGING_CONFIGURED
    if _LOGGING_CONFIGURED:
        return
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    for name in ("agent_relay", "agent_relay.worker"):
        logger = logging.getLogger(name)
        logger.handlers = [handler]
        logger.propagate = False
        logger.setLevel(logging.INFO)
    _LOGGING_CONFIGURED = True


def configure_telemetry() -> None:
    global _TELEMETRY_CONFIGURED
    if _TELEMETRY_CONFIGURED or not telemetry_enabled():
        return

    from opentelemetry import trace
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    attributes = {"service.name": SERVICE_NAME}
    environment = os.getenv("DEPLOYMENT_ENVIRONMENT") or os.getenv("OTEL_DEPLOYMENT_ENVIRONMENT")
    if environment:
        attributes["deployment.environment"] = environment

    provider = TracerProvider(resource=Resource.create(attributes))
    endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
    if endpoint:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

        # Let the exporter resolve OTEL_EXPORTER_OTLP_ENDPOINT to /v1/traces.
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))

    trace.set_tracer_provider(provider)
    _TELEMETRY_CONFIGURED = True


def instrument_app(app: Any) -> None:
    if not telemetry_enabled():
        return
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

    FastAPIInstrumentor.instrument_app(app)


def get_tracer(name: str) -> Any:
    from opentelemetry import trace

    return trace.get_tracer(name)


@contextlib.contextmanager
def create_task_span(sender_id: str, recipient_id: str):
    if not telemetry_enabled():
        yield None
        return
    tracer = get_tracer("agent_relay")
    with tracer.start_as_current_span("agent_relay.create_task") as span:
        span.set_attribute("agent.id", sender_id)
        span.set_attribute("task.recipient_id", recipient_id)
        yield span


__all__ = [
    "REQUEST_ID_HEADER",
    "SERVICE_NAME",
    "configure_logging",
    "configure_telemetry",
    "create_task_span",
    "current_trace_id",
    "get_tracer",
    "instrument_app",
    "resolve_request_id",
    "telemetry_enabled",
]
