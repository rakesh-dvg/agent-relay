"""Read-only recovery verification from bounded observability evidence."""

from __future__ import annotations

from typing import Any

ALERT_THRESHOLD = 0.05


def _metric_value(metrics: dict[str, Any], name: str) -> float | None:
    samples = metrics.get(name, [])
    if not isinstance(samples, list) or not samples:
        return None
    first = samples[0]
    if not isinstance(first, dict):
        return None
    try:
        return float(first.get("value"))
    except (TypeError, ValueError):
        return None


def verify_recovery(
    evidence: dict[str, Any],
    executed_action: str | None,
) -> dict[str, Any]:
    alert = evidence.get("alert", {})
    alert_name = alert.get("name", "unknown") if isinstance(alert, dict) else "unknown"
    state = str(alert.get("state", "unknown")).lower() if isinstance(alert, dict) else "unknown"
    metrics = evidence.get("metrics", {}) if isinstance(evidence.get("metrics"), dict) else {}

    request_rate = _metric_value(metrics, "http_request_rate")
    error_rate = _metric_value(metrics, "http_5xx_rate")
    error_ratio = _metric_value(metrics, "http_5xx_ratio")

    checks = {
        "alert_state": state,
        "http_request_rate": request_rate,
        "http_5xx_rate": error_rate,
        "http_5xx_ratio": error_ratio,
    }

    if executed_action == "no_action" and state != "firing":
        return {
            "verification_state": "not_applicable",
            "alert_name": alert_name,
            "checks": checks,
            "reason": "No remediation was executed and the alert is not firing.",
        }

    if state == "firing" or (error_ratio is not None and error_ratio >= ALERT_THRESHOLD):
        return {
            "verification_state": "still_degraded",
            "alert_name": alert_name,
            "checks": checks,
            "reason": "Alert is firing or the HTTP 5xx ratio remains elevated in the evidence packet.",
        }

    if state == "inactive":
        return {
            "verification_state": "recovered",
            "alert_name": alert_name,
            "checks": checks,
            "reason": "Alert is inactive and the HTTP 5xx ratio is below the incident threshold.",
        }

    return {
        "verification_state": "verification_failed",
        "alert_name": alert_name,
        "checks": checks,
        "reason": "Recovery could not be determined from the available read-only evidence.",
    }


__all__ = ["verify_recovery"]
