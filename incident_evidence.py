"""Bounded, read-only incident evidence collection for Agent Relay."""

from __future__ import annotations

import json
import os
import re
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SERVICE_NAME = "agent-relay"
ALERT_NAME = "AgentRelayHighHTTP5xxRate"

DEFAULT_PROMETHEUS_URL = "http://127.0.0.1:9090"
DEFAULT_LOKI_URL = "http://127.0.0.1:3100"
DEFAULT_TEMPO_URL = "http://127.0.0.1:3200"
DEFAULT_OUTPUT_PATH = Path("evidence/incident-evidence.json")

HTTP_TIMEOUT_SECONDS = 5.0
MAX_RESPONSE_BYTES = 256_000
MAX_LOG_ENTRIES = 50
MAX_TRACES = 10
LOOKBACK_SECONDS = 900

ALLOWLISTED_PROMQL: dict[str, str] = {
    "http_request_rate": "sum(rate(agent_relay_http_requests_total[5m]))",
    "http_5xx_rate": 'sum(rate(agent_relay_http_requests_total{status_code=~"5.."}[5m]))',
    "http_5xx_ratio": (
        "sum(rate(agent_relay_http_requests_total{status_code=~\"5..\"}[5m])) "
        "/ sum(rate(agent_relay_http_requests_total[5m]))"
    ),
    "task_created_rate_by_status": "sum(rate(agent_relay_task_created_total[5m])) by (status)",
    "task_error_rate_by_type": "sum(rate(agent_relay_task_errors_total[5m])) by (error_type)",
}

ALLOWLISTED_LOGQL = '{container=~"agent-relay-app.*"} |= "http request completed"'
ALLOWLISTED_TEMPO_TAGS = "service.name=agent-relay"

SENSITIVE_KEY_PATTERN = re.compile(
    r"(authorization|password|secret|credential|token|api[_-]?key|bearer|input)",
    re.IGNORECASE,
)
SENSITIVE_VALUE_PATTERNS = (
    re.compile(r"Bearer\s+\S+", re.IGNORECASE),
    re.compile(r"\bagt_[A-Za-z0-9._-]+\b"),
    re.compile(r"postgresql(?:\+[A-Za-z]+)?://[^\s\"']+", re.IGNORECASE),
)


class EvidenceCollectionError(Exception):
    """Raised when bounded evidence collection fails."""


class ResponseTooLargeError(EvidenceCollectionError):
    """Raised when an observability response exceeds the configured limit."""


def service_urls() -> dict[str, str]:
    return {
        "prometheus": os.getenv("PROMETHEUS_URL", DEFAULT_PROMETHEUS_URL).rstrip("/"),
        "loki": os.getenv("LOKI_URL", DEFAULT_LOKI_URL).rstrip("/"),
        "tempo": os.getenv("TEMPO_URL", DEFAULT_TEMPO_URL).rstrip("/"),
    }


def application_version(project_root: Path | None = None) -> str:
    root = project_root or Path(__file__).resolve().parent
    pyproject = root / "pyproject.toml"
    if not pyproject.is_file():
        return "unknown"
    try:
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return "unknown"
    version = data.get("project", {}).get("version")
    return str(version) if version else "unknown"


def is_sensitive_key(key: str) -> bool:
    return bool(SENSITIVE_KEY_PATTERN.search(key))


def redact_string(value: str) -> str:
    redacted = value
    for pattern in SENSITIVE_VALUE_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


def redact_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if is_sensitive_key(key) else redact_value(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, str):
        return redact_string(value)
    return value


def redact_log_entry(line: str) -> str:
    try:
        payload = json.loads(line)
    except json.JSONDecodeError:
        return redact_string(line)
    return json.dumps(redact_value(payload), ensure_ascii=True)


def fetch_json(url: str, timeout: float = HTTP_TIMEOUT_SECONDS, max_bytes: int = MAX_RESPONSE_BYTES) -> Any:
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(max_bytes + 1)
    except urllib.error.URLError as exc:
        raise EvidenceCollectionError(f"request failed for {url}: {exc}") from exc
    if len(body) > max_bytes:
        raise ResponseTooLargeError(f"response exceeded {max_bytes} bytes for {url}")
    try:
        return json.loads(body.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise EvidenceCollectionError(f"invalid JSON response from {url}") from exc


def prometheus_instant_query(base_url: str, promql: str) -> list[dict[str, Any]]:
    if promql not in ALLOWLISTED_PROMQL.values():
        raise EvidenceCollectionError("attempted to run a non-allowlisted PromQL query")
    query = urllib.parse.urlencode({"query": promql})
    payload = fetch_json(f"{base_url}/api/v1/query?{query}")
    if payload.get("status") != "success":
        raise EvidenceCollectionError(f"prometheus query failed: {promql}")
    return payload.get("data", {}).get("result", [])


def collect_alert_state(base_url: str) -> dict[str, Any]:
    payload = fetch_json(f"{base_url}/api/v1/alerts")
    if payload.get("status") != "success":
        raise EvidenceCollectionError("prometheus alerts query failed")
    matches = [
        alert
        for alert in payload.get("data", {}).get("alerts", [])
        if alert.get("labels", {}).get("alertname") == ALERT_NAME
    ]
    if not matches:
        rules_payload = fetch_json(f"{base_url}/api/v1/rules")
        rule_state = "unknown"
        labels: dict[str, Any] = {"alertname": ALERT_NAME, "service": SERVICE_NAME}
        annotations: dict[str, Any] = {}
        if rules_payload.get("status") == "success":
            for group in rules_payload.get("data", {}).get("groups", []):
                for rule in group.get("rules", []):
                    if rule.get("name") == ALERT_NAME:
                        rule_state = rule.get("state", "unknown")
                        labels = {"alertname": ALERT_NAME, "service": SERVICE_NAME, **rule.get("labels", {})}
                        annotations = rule.get("annotations", {})
                        break
        return {
            "name": ALERT_NAME,
            "state": rule_state,
            "labels": labels,
            "annotations": annotations,
        }
    active = matches[0]
    return {
        "name": ALERT_NAME,
        "state": active.get("state", "unknown"),
        "labels": active.get("labels", {}),
        "annotations": active.get("annotations", {}),
    }


def vector_samples(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    samples: list[dict[str, Any]] = []
    for result in results:
        metric = result.get("metric", {})
        value = result.get("value", [])
        if len(value) == 2:
            samples.append({"metric": metric, "value": value[1]})
    return samples


def collect_metrics(base_url: str) -> dict[str, Any]:
    metrics: dict[str, Any] = {}
    for name, promql in ALLOWLISTED_PROMQL.items():
        metrics[name] = vector_samples(prometheus_instant_query(base_url, promql))
    return metrics


def collect_logs(base_url: str, now: datetime | None = None) -> list[dict[str, Any]]:
    if ALLOWLISTED_LOGQL != '{container=~"agent-relay-app.*"} |= "http request completed"':
        raise EvidenceCollectionError("attempted to run a non-allowlisted LogQL query")
    current = now or datetime.now(timezone.utc)
    start = int((current.timestamp() - LOOKBACK_SECONDS) * 1_000_000_000)
    end = int(current.timestamp() * 1_000_000_000)
    params = urllib.parse.urlencode(
        {
            "query": ALLOWLISTED_LOGQL,
            "start": str(start),
            "end": str(end),
            "limit": str(MAX_LOG_ENTRIES),
            "direction": "backward",
        }
    )
    payload = fetch_json(f"{base_url}/loki/api/v1/query_range?{params}")
    if payload.get("status") != "success":
        raise EvidenceCollectionError("loki query failed")
    entries: list[dict[str, Any]] = []
    for stream in payload.get("data", {}).get("result", []):
        labels = stream.get("stream", {})
        for timestamp, line in stream.get("values", []):
            entries.append(
                {
                    "timestamp_ns": timestamp,
                    "labels": labels,
                    "message": redact_log_entry(line),
                }
            )
            if len(entries) >= MAX_LOG_ENTRIES:
                return entries
    return entries


def collect_traces(base_url: str) -> list[dict[str, Any]]:
    params = urllib.parse.urlencode(
        {
            "tags": ALLOWLISTED_TEMPO_TAGS,
            "limit": str(MAX_TRACES),
        }
    )
    payload = fetch_json(f"{base_url}/api/search?{params}")
    traces = payload.get("traces", [])
    return [
        {
            "trace_id": trace.get("traceID"),
            "root_service_name": trace.get("rootServiceName"),
            "root_trace_name": trace.get("rootTraceName"),
            "duration_ms": trace.get("durationMs"),
        }
        for trace in traces[:MAX_TRACES]
    ]


def build_evidence_packet(
    prometheus_url: str | None = None,
    loki_url: str | None = None,
    tempo_url: str | None = None,
    project_root: Path | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    urls = service_urls()
    prom = (prometheus_url or urls["prometheus"]).rstrip("/")
    loki = (loki_url or urls["loki"]).rstrip("/")
    tempo = (tempo_url or urls["tempo"]).rstrip("/")
    current = now or datetime.now(timezone.utc)
    return {
        "generated_at": current.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "service": SERVICE_NAME,
        "alert": collect_alert_state(prom),
        "metrics": collect_metrics(prom),
        "logs": collect_logs(loki, now=current),
        "traces": collect_traces(tempo),
        "version": application_version(project_root),
        "collection_limits": {
            "http_timeout_seconds": HTTP_TIMEOUT_SECONDS,
            "max_response_bytes": MAX_RESPONSE_BYTES,
            "max_log_entries": MAX_LOG_ENTRIES,
            "max_traces": MAX_TRACES,
            "lookback_seconds": LOOKBACK_SECONDS,
        },
    }


def write_evidence_packet(
    output_path: Path | None = None,
    prometheus_url: str | None = None,
    loki_url: str | None = None,
    tempo_url: str | None = None,
    project_root: Path | None = None,
) -> Path:
    destination = output_path or DEFAULT_OUTPUT_PATH
    packet = build_evidence_packet(
        prometheus_url=prometheus_url,
        loki_url=loki_url,
        tempo_url=tempo_url,
        project_root=project_root,
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(packet, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    return destination


__all__ = [
    "ALERT_NAME",
    "ALLOWLISTED_LOGQL",
    "ALLOWLISTED_PROMQL",
    "ALLOWLISTED_TEMPO_TAGS",
    "DEFAULT_LOKI_URL",
    "DEFAULT_OUTPUT_PATH",
    "DEFAULT_PROMETHEUS_URL",
    "DEFAULT_TEMPO_URL",
    "HTTP_TIMEOUT_SECONDS",
    "LOOKBACK_SECONDS",
    "MAX_LOG_ENTRIES",
    "MAX_RESPONSE_BYTES",
    "MAX_TRACES",
    "EvidenceCollectionError",
    "ResponseTooLargeError",
    "application_version",
    "build_evidence_packet",
    "collect_alert_state",
    "collect_logs",
    "collect_metrics",
    "collect_traces",
    "fetch_json",
    "redact_log_entry",
    "service_urls",
    "write_evidence_packet",
]
