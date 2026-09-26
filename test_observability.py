"""Focused tests for structured logging and optional OpenTelemetry."""

from __future__ import annotations

import io
import json
import logging
import os
import re
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

_observability_db = Path(tempfile.gettempdir()) / "agent-relay-observability.db"
os.environ.setdefault("RELAY_DATABASE_URL", f"sqlite:///{_observability_db.as_posix()}")
os.environ.setdefault("OTEL_SDK_DISABLED", "true")

import main
from database import Base, engine
from telemetry import JsonFormatter, configure_telemetry, telemetry_enabled


@pytest.fixture(autouse=True)
def empty_database():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    yield
    Base.metadata.drop_all(engine)


@pytest.fixture
def agent_relay_logs():
    buffer = io.StringIO()
    handler = logging.StreamHandler(buffer)
    handler.setFormatter(JsonFormatter())
    logger = logging.getLogger("agent_relay")
    logger.addHandler(handler)
    try:
        yield buffer
    finally:
        logger.removeHandler(handler)


def register(client: TestClient, name: str) -> tuple[dict, dict[str, str]]:
    response = client.post("/api/v1/agents", json={"name": name})
    assert response.status_code == 201
    data = response.json()
    return data, {"Authorization": f"Bearer {data['token']}"}


def test_request_id_is_generated_and_returned():
    with TestClient(main.app) as client:
        response = client.get("/health")
        assert response.status_code == 200
        request_id = response.headers.get("X-Request-ID")
        assert request_id
        assert re.fullmatch(r"[0-9a-f-]{36}", request_id)


def test_request_id_can_be_reused_from_header():
    with TestClient(main.app) as client:
        response = client.get("/health", headers={"X-Request-ID": "client-req-123"})
        assert response.status_code == 200
        assert response.headers.get("X-Request-ID") == "client-req-123"


def test_task_creation_still_works_with_observability_baseline():
    with TestClient(main.app) as client:
        sender, sender_headers = register(client, "sender")
        recipient, _ = register(client, "recipient")
        response = client.post(
            "/api/v1/tasks",
            headers=sender_headers,
            json={"to": recipient["agent_id"], "input": "hello observability"},
        )
        assert response.status_code == 201
        assert response.json()["status"] == "queued"
        assert "task_id" in response.json()


def test_configure_telemetry_without_collector(monkeypatch):
    monkeypatch.setenv("OTEL_SDK_DISABLED", "false")
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    import telemetry as telemetry_module

    telemetry_module._TELEMETRY_CONFIGURED = False
    configure_telemetry()
    assert telemetry_enabled()


def test_request_logs_do_not_include_sensitive_values(agent_relay_logs):
    secret_input = "top-secret-task-input-xyz"
    with TestClient(main.app) as client:
        sender, sender_headers = register(client, "sender")
        recipient, _ = register(client, "recipient")
        secret_token = sender["token"]
        response = client.post(
            "/api/v1/tasks",
            headers=sender_headers,
            json={"to": recipient["agent_id"], "input": secret_input},
        )
        assert response.status_code == 201

    log_blob = agent_relay_logs.getvalue()
    assert secret_token not in log_blob
    assert secret_input not in log_blob
    assert "Bearer" not in log_blob

    task_log = next(
        line
        for line in log_blob.splitlines()
        if '"http.route": "/api/v1/tasks"' in line and '"message": "http request completed"' in line
    )
    payload = json.loads(task_log)
    assert payload["http.method"] == "POST"
    assert payload["http.status_code"] == 201
    assert payload["request_id"]
    assert payload["service.name"] == "agent-relay"


def _metric_line(metrics_text: str, metric_name: str, labels: str) -> str | None:
    needle = f"{metric_name}{{{labels}}}"
    for line in metrics_text.splitlines():
        if line.startswith(needle):
            return line
    return None


def test_metrics_endpoint_returns_prometheus_payload():
    with TestClient(main.app) as client:
        response = client.get("/metrics")
        assert response.status_code == 200
        assert "text/plain" in response.headers["content-type"]
        body = response.text
        assert "agent_relay_http_requests_total" in body
        assert "agent_relay_http_request_duration_seconds" in body
        assert "agent_relay_task_created_total" in body
        assert "agent_relay_task_errors_total" in body


def test_http_request_metrics_are_incremented():
    with TestClient(main.app) as client:
        response = client.get("/health")
        assert response.status_code == 200
        metrics = client.get("/metrics").text
        line = _metric_line(
            metrics,
            "agent_relay_http_requests_total",
            'method="GET",route="/health",status_code="200"',
        )
        assert line is not None
        assert float(line.rsplit(" ", 1)[1]) >= 1.0


def test_task_metrics_are_incremented():
    with TestClient(main.app) as client:
        sender, sender_headers = register(client, "sender")
        recipient, _ = register(client, "recipient")
        response = client.post(
            "/api/v1/tasks",
            headers=sender_headers,
            json={"to": recipient["agent_id"], "input": "hello metrics"},
        )
        assert response.status_code == 201
        metrics = client.get("/metrics").text
        created_line = _metric_line(metrics, "agent_relay_task_created_total", 'status="queued"')
        assert created_line is not None
        assert float(created_line.rsplit(" ", 1)[1]) >= 1.0

        missing_recipient = client.post(
            "/api/v1/tasks",
            headers=sender_headers,
            json={"to": "agent_missing", "input": "hello metrics"},
        )
        assert missing_recipient.status_code == 404
        metrics = client.get("/metrics").text
        error_line = _metric_line(metrics, "agent_relay_task_errors_total", 'error_type="not_found"')
        assert error_line is not None
        assert float(error_line.rsplit(" ", 1)[1]) >= 1.0


def test_metric_labels_are_bounded_and_do_not_include_ids():
    secret_input = "super-secret-task-input"
    with TestClient(main.app) as client:
        sender, sender_headers = register(client, "sender")
        recipient, _ = register(client, "recipient")
        created = client.post(
            "/api/v1/tasks",
            headers=sender_headers,
            json={"to": recipient["agent_id"], "input": secret_input},
        )
        assert created.status_code == 201
        task_id = created.json()["task_id"]
        assert client.get(f"/api/v1/tasks/{task_id}", headers=sender_headers).status_code == 200

        metrics = client.get("/metrics").text
        assert task_id not in metrics
        assert recipient["agent_id"] not in metrics
        assert secret_input not in metrics
        assert sender["token"] not in metrics
        assert 'route="/api/v1/tasks/{task_id}"' in metrics
        assert re.search(
            r'agent_relay_http_requests_total\{method="GET",route="/api/v1/tasks/\{task_id\}",status_code="200"\}',
            metrics,
        )
