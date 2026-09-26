"""Tests for bounded incident evidence collection."""

from __future__ import annotations

import io
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

import pytest

import incident_evidence as evidence


@pytest.fixture
def project_root(tmp_path: Path) -> Path:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[project]\nname = "agent-relay"\nversion = "0.1.0"\n', encoding="utf-8")
    return tmp_path


def test_only_allowlisted_promql_is_used():
    assert set(evidence.ALLOWLISTED_PROMQL) == {
        "http_request_rate",
        "http_5xx_rate",
        "http_5xx_ratio",
        "task_created_rate_by_status",
        "task_error_rate_by_type",
    }
    with pytest.raises(evidence.EvidenceCollectionError, match="non-allowlisted PromQL"):
        evidence.prometheus_instant_query("http://prometheus", "up")


def test_fetch_json_enforces_response_limit():
    class FakeResponse:
        def __init__(self) -> None:
            self._payload = b'{"status":"success"}'

        def read(self, max_bytes: int) -> bytes:
            return self._payload

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            return None

    with mock.patch("urllib.request.urlopen", return_value=FakeResponse()):
        payload = evidence.fetch_json("http://example", max_bytes=32)
        assert payload["status"] == "success"

    oversized = io.BytesIO(b"x" * 10)

    class OversizedResponse:
        def read(self, max_bytes: int) -> bytes:
            return oversized.read(max_bytes + 1)

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            return None

    with mock.patch("urllib.request.urlopen", return_value=OversizedResponse()):
        with pytest.raises(evidence.ResponseTooLargeError):
            evidence.fetch_json("http://example", max_bytes=4)


def test_sensitive_fields_are_redacted():
    raw = json.dumps(
        {
            "message": "http request completed",
            "request_id": "req-123",
            "trace_id": "abc123",
            "http.route": "/api/v1/tasks",
            "http.status_code": 201,
            "Authorization": "Bearer agt_secret",
            "input": "top-secret-task-input",
        }
    )
    redacted = json.loads(evidence.redact_log_entry(raw))
    assert redacted["request_id"] == "req-123"
    assert redacted["trace_id"] == "abc123"
    assert redacted["http.route"] == "/api/v1/tasks"
    assert redacted["Authorization"] == "[REDACTED]"
    assert redacted["input"] == "[REDACTED]"
    assert "agt_secret" not in json.dumps(redacted)
    assert "top-secret-task-input" not in json.dumps(redacted)


def test_build_evidence_packet_structure(project_root: Path):
    fixed_now = datetime(2026, 9, 26, 2, 0, tzinfo=timezone.utc)

    def fake_fetch_json(url: str, timeout: float = evidence.HTTP_TIMEOUT_SECONDS, max_bytes: int = evidence.MAX_RESPONSE_BYTES):
        if url.endswith("/api/v1/alerts"):
            return {"status": "success", "data": {"alerts": []}}
        if url.endswith("/api/v1/rules"):
            return {
                "status": "success",
                "data": {
                    "groups": [
                        {
                            "rules": [
                                {
                                    "name": evidence.ALERT_NAME,
                                    "state": "inactive",
                                    "labels": {"severity": "critical", "service": "agent-relay"},
                                    "annotations": {"summary": "ok"},
                                }
                            ]
                        }
                    ]
                },
            }
        if "/api/v1/query?" in url:
            return {"status": "success", "data": {"result": [{"metric": {}, "value": [1, "0.5"]}]}}
        if "/loki/api/v1/query_range?" in url:
            return {
                "status": "success",
                "data": {
                    "result": [
                        {
                            "stream": {"container": "agent-relay-app-1", "level": "INFO"},
                            "values": [
                                [
                                    "1",
                                    json.dumps(
                                        {
                                            "message": "http request completed",
                                            "request_id": "req-1",
                                            "trace_id": "trace-1",
                                            "http.route": "/health",
                                            "http.status_code": 200,
                                        }
                                    ),
                                ]
                            ],
                        }
                    ]
                },
            }
        if url.endswith("/api/search?tags=service.name%3Dagent-relay&limit=10"):
            return {
                "traces": [
                    {
                        "traceID": "trace-1",
                        "rootServiceName": "agent-relay",
                        "rootTraceName": "GET /health",
                        "durationMs": 3,
                    }
                ]
            }
        raise AssertionError(f"unexpected url: {url}")

    with mock.patch.object(evidence, "fetch_json", side_effect=fake_fetch_json):
        packet = evidence.build_evidence_packet(
            prometheus_url="http://prometheus",
            loki_url="http://loki",
            tempo_url="http://tempo",
            project_root=project_root,
            now=fixed_now,
        )

    assert packet["service"] == "agent-relay"
    assert packet["version"] == "0.1.0"
    assert packet["alert"]["name"] == evidence.ALERT_NAME
    assert packet["alert"]["state"] == "inactive"
    assert packet["metrics"]["http_request_rate"]
    assert packet["logs"][0]["message"]
    assert packet["traces"][0]["trace_id"] == "trace-1"
    assert packet["collection_limits"]["max_log_entries"] == evidence.MAX_LOG_ENTRIES


def test_script_rejects_arbitrary_query_arguments():
    script = Path(__file__).resolve().parent / "scripts" / "collect_incident_evidence.py"
    result = subprocess.run(
        [sys.executable, str(script), "--promql", "up"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert "does not accept command-line query arguments" in result.stderr


def test_collector_does_not_execute_shell_commands(project_root: Path, tmp_path: Path):
    with (
        mock.patch.object(
            evidence,
            "fetch_json",
            side_effect=evidence.EvidenceCollectionError("offline"),
        ),
        mock.patch("subprocess.run", side_effect=AssertionError("shell commands are not allowed")),
        mock.patch("subprocess.Popen", side_effect=AssertionError("shell commands are not allowed")),
        mock.patch("os.system", side_effect=AssertionError("shell commands are not allowed")),
    ):
        with pytest.raises(evidence.EvidenceCollectionError):
            evidence.build_evidence_packet(project_root=project_root)


def test_write_evidence_packet(project_root: Path, tmp_path: Path):
    output = tmp_path / "incident-evidence.json"

    def fake_fetch_json(url: str, timeout: float = evidence.HTTP_TIMEOUT_SECONDS, max_bytes: int = evidence.MAX_RESPONSE_BYTES):
        if url.endswith("/api/v1/alerts"):
            return {"status": "success", "data": {"alerts": []}}
        if url.endswith("/api/v1/rules"):
            return {"status": "success", "data": {"groups": [{"rules": []}]}}
        if "/api/v1/query?" in url:
            return {"status": "success", "data": {"result": []}}
        if "/loki/api/v1/query_range?" in url:
            return {"status": "success", "data": {"result": []}}
        if "/api/search?" in url:
            return {"traces": []}
        raise AssertionError(url)

    with mock.patch.object(evidence, "fetch_json", side_effect=fake_fetch_json):
        written = evidence.write_evidence_packet(output_path=output, project_root=project_root)

    payload = json.loads(written.read_text(encoding="utf-8"))
    assert written == output
    assert payload["service"] == "agent-relay"
    assert "metrics" in payload
