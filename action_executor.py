"""Bounded executor for policy-authorized incident actions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from autonomy_policy import POLICY_AUTHORIZED_ACTIONS, PolicyDecision


class ExecutionRefusedError(Exception):
    """Raised when an action was not authorized by policy."""


@dataclass(frozen=True)
class ExecutionResult:
    executed_action: str | None
    execution_result: str
    status: str
    reason: str
    details: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "executed_action": self.executed_action,
            "execution_result": self.execution_result,
            "status": self.status,
            "reason": self.reason,
            "details": self.details,
        }


def execute_authorized_action(decision: PolicyDecision) -> ExecutionResult:
    if decision.policy_decision == "denied" or not decision.authorized_action:
        return ExecutionResult(
            executed_action=None,
            execution_result="policy_denied",
            status="refused",
            reason=decision.reason,
            details={"proposed_action": decision.proposed_action},
        )

    action = decision.authorized_action
    if action not in POLICY_AUTHORIZED_ACTIONS:
        return ExecutionResult(
            executed_action=None,
            execution_result="unauthorized",
            status="refused",
            reason=f"Executor refuses unauthorized action '{action}'.",
            details={"proposed_action": decision.proposed_action},
        )

    if decision.policy_decision not in {"authorized", "escalated"}:
        return ExecutionResult(
            executed_action=None,
            execution_result="policy_denied",
            status="refused",
            reason=decision.reason,
            details={"proposed_action": decision.proposed_action},
        )

    if action == "no_action":
        return ExecutionResult(
            executed_action="no_action",
            execution_result="success",
            status="completed",
            reason="No infrastructure mutation was required.",
            details={"mutation_performed": False},
        )

    if action == "escalate":
        return ExecutionResult(
            executed_action="escalate",
            execution_result="escalated",
            status="completed",
            reason="Incident was escalated for human review without infrastructure mutation.",
            details={"mutation_performed": False},
        )

    return ExecutionResult(
        executed_action=None,
        execution_result="unauthorized",
        status="refused",
        reason=f"Action '{action}' is not implemented in the bounded executor.",
        details={"proposed_action": decision.proposed_action},
    )


__all__ = [
    "ExecutionRefusedError",
    "ExecutionResult",
    "execute_authorized_action",
]
