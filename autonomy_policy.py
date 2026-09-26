"""Autonomy policy for authorizing bounded incident actions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from incident_responder import ALLOWED_ACTION_TYPES, FORBIDDEN_RESPONSE_KEYS

POLICY_AUTHORIZED_ACTIONS = frozenset({"no_action", "escalate"})
REMEDIATION_ACTIONS = frozenset({"restart_application", "rollback_application", "scale_application"})


@dataclass(frozen=True)
class PolicyDecision:
    proposed_action: str
    authorized_action: str | None
    policy_decision: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "proposed_action": self.proposed_action,
            "authorized_action": self.authorized_action,
            "policy_decision": self.policy_decision,
            "reason": self.reason,
        }


def _forbidden_fields_present(value: Any) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower() in FORBIDDEN_RESPONSE_KEYS:
                return True
            if _forbidden_fields_present(item):
                return True
    elif isinstance(value, list):
        return any(_forbidden_fields_present(item) for item in value)
    return False


def proposed_action_type(assessment: dict[str, Any]) -> str:
    proposed = assessment.get("proposed_action", {})
    if not isinstance(proposed, dict):
        return "unknown"
    action_type = proposed.get("action_type")
    return str(action_type) if action_type is not None else "unknown"


def assessment_status(assessment: dict[str, Any]) -> str:
    return str(assessment.get("status", "unknown"))


def alert_state(evidence: dict[str, Any]) -> str:
    alert = evidence.get("alert", {})
    if not isinstance(alert, dict):
        return "unknown"
    return str(alert.get("state", "unknown")).lower()


def evaluate_policy(evidence: dict[str, Any], assessment: dict[str, Any]) -> PolicyDecision:
    proposed = proposed_action_type(assessment)
    status = assessment_status(assessment)
    alert = alert_state(evidence)

    if _forbidden_fields_present(assessment):
        return PolicyDecision(
            proposed_action=proposed,
            authorized_action="escalate",
            policy_decision="escalated",
            reason="Assessment contains forbidden command-like fields and requires human review.",
        )

    if status != "valid":
        return PolicyDecision(
            proposed_action=proposed,
            authorized_action="escalate",
            policy_decision="escalated",
            reason="Assessment status is invalid; automatic remediation is not permitted.",
        )

    if proposed not in ALLOWED_ACTION_TYPES:
        return PolicyDecision(
            proposed_action=proposed,
            authorized_action="escalate",
            policy_decision="escalated",
            reason="Proposed action is not in the approved AI action vocabulary.",
        )

    if proposed not in POLICY_AUTHORIZED_ACTIONS:
        return PolicyDecision(
            proposed_action=proposed,
            authorized_action=None,
            policy_decision="denied",
            reason=(
                f"Policy does not authorize '{proposed}'. "
                "Only no_action and escalate may execute automatically."
            ),
        )

    if alert != "firing" and proposed in REMEDIATION_ACTIONS:
        return PolicyDecision(
            proposed_action=proposed,
            authorized_action=None,
            policy_decision="denied",
            reason="Remediation actions are not permitted while the alert is inactive.",
        )

    if alert != "firing" and proposed not in {"no_action", "escalate"}:
        return PolicyDecision(
            proposed_action=proposed,
            authorized_action=None,
            policy_decision="denied",
            reason="Only no_action or escalate are permitted while the alert is inactive.",
        )

    return PolicyDecision(
        proposed_action=proposed,
        authorized_action=proposed,
        policy_decision="authorized",
        reason=f"Policy authorized '{proposed}' based on the current evidence and assessment.",
    )


__all__ = [
    "POLICY_AUTHORIZED_ACTIONS",
    "REMEDIATION_ACTIONS",
    "PolicyDecision",
    "alert_state",
    "assessment_status",
    "evaluate_policy",
    "proposed_action_type",
]
