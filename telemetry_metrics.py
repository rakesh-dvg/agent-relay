"""Application Prometheus metrics for Agent Relay."""

from __future__ import annotations

from typing import Any

from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

HTTP_REQUESTS = Counter(
    "agent_relay_http_requests_total",
    "Total HTTP requests handled by Agent Relay.",
    ["method", "route", "status_code"],
)

HTTP_REQUEST_DURATION = Histogram(
    "agent_relay_http_request_duration_seconds",
    "HTTP request latency in seconds.",
    ["method", "route"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

TASK_CREATED = Counter(
    "agent_relay_task_created_total",
    "Tasks created or idempotently returned via POST /api/v1/tasks.",
    ["status"],
)

TASK_ERRORS = Counter(
    "agent_relay_task_errors_total",
    "Task creation errors.",
    ["error_type"],
)

TASK_ERROR_TYPES = frozenset({"validation", "not_found", "unauthorized", "conflict", "internal", "unknown"})

RELAY_ERROR_TO_TYPE = {
    "invalid_input": "validation",
    "invalid_cursor": "validation",
    "body_too_large": "validation",
    "not_found": "not_found",
    "missing_credentials": "unauthorized",
    "invalid_credentials": "unauthorized",
    "invalid_enrollment": "unauthorized",
    "idempotency_conflict": "conflict",
    "conflicting_terminal": "conflict",
    "stale_claim": "conflict",
    "storage_error": "internal",
}


def normalize_route(request: Any) -> str:
    route = request.scope.get("route")
    if route is not None and hasattr(route, "path"):
        return route.path
    return "unmatched"


def relay_error_type(code: str) -> str:
    error_type = RELAY_ERROR_TO_TYPE.get(code, "unknown")
    if error_type not in TASK_ERROR_TYPES:
        return "unknown"
    return error_type


def record_http_request(method: str, route: str, status_code: int, duration_seconds: float) -> None:
    HTTP_REQUESTS.labels(method=method, route=route, status_code=str(status_code)).inc()
    HTTP_REQUEST_DURATION.labels(method=method, route=route).observe(duration_seconds)


def record_task_created(status: str) -> None:
    TASK_CREATED.labels(status=status).inc()


def record_task_error(error_type: str) -> None:
    if error_type not in TASK_ERROR_TYPES:
        error_type = "unknown"
    TASK_ERRORS.labels(error_type=error_type).inc()


def metrics_payload() -> tuple[bytes, str]:
    return generate_latest(), CONTENT_TYPE_LATEST


def is_task_create_request(request: Any) -> bool:
    route = request.scope.get("route")
    return request.method == "POST" and route is not None and route.path == "/api/v1/tasks"


__all__ = [
    "HTTP_REQUEST_DURATION",
    "HTTP_REQUESTS",
    "TASK_CREATED",
    "TASK_ERRORS",
    "is_task_create_request",
    "metrics_payload",
    "normalize_route",
    "record_http_request",
    "record_task_created",
    "record_task_error",
    "relay_error_type",
]
