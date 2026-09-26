"""Tests for autonomy policy, bounded execution, and recovery verification."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

import action_executor as executor
import autonomy_policy as policy
import recovery_verification as verification
from scripts.apply_incident_action import apply_incident_action, build_test_assessment


@pytest.fixture
def healthy_evidence() -> dict:
    return {
        "service": "agent-relay",
        "alert": {"name": "AgentRelayHighHTTP5xxRate", "state": "inactive"},
        "metrics": {
            "http_request_rate": [{"metric": {}, "value": "0.05"}],
            "http_5xx_rate": [],
            "http_5xx_ratio": [],
        },
        "logs": [],
        "traces": [],
    }


@pytest.fixture
def firing_evidence(healthy_evidence: dict) -> dict:
    payload = json.loads(json.dumps(healthy_evidence))
    payload["alert"]["state"] = "firing"
    payload["metrics"]["http_5xx_ratio"] = [{"metric": {}, "value": "0.08"}]
    return payload


def assessment(action_type: str, status: str = "valid", extra: dict | None = None) -> dict:
    payload = {
        "status": status,
        "incident_summary": "summary",
        "severity": "low",
        "user_impact": "impact",
        "evidence": ["evidence item"],
        "likely_cause": "cause",
        "confidence": "high",
        "proposed_action": {"action_type": action_type, "reason": "because"},
        "escalate": action_type == "escalate",
    }
    if extra:
        payload.update(extra)
    return payload


def test_healthy_no_action_is_authorized_and_writes_audit(healthy_evidence: dict, tmp_path: Path):
    evidence_path = tmp_path / "evidence.json"
    assessment_path = tmp_path / "assessment.json"
    audit_path = tmp_path / "audit.json"
    evidence_path.write_text(json.dumps(healthy_evidence), encoding="utf-8")
    assessment_path.write_text(json.dumps(assessment("no_action")), encoding="utf-8")

    apply_incident_action(evidence_path, assessment_path, audit_path)

    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    assert audit["policy_decision"] == "authorized"
    assert audit["proposed_action"] == "no_action"
    assert audit["executed_action"] == "no_action"
    assert audit["execution_result"] == "success"
    assert audit["verification_state"] == "not_applicable"


def test_healthy_restart_is_denied(healthy_evidence: dict):
    decision = policy.evaluate_policy(healthy_evidence, assessment("restart_application"))
    result = executor.execute_authorized_action(decision)
    assert decision.policy_decision == "denied"
    assert result.executed_action is None
    assert result.execution_result == "policy_denied"


def test_firing_restart_is_still_denied(firing_evidence: dict):
    decision = policy.evaluate_policy(firing_evidence, assessment("restart_application"))
    result = executor.execute_authorized_action(decision)
    assert decision.policy_decision == "denied"
    assert result.executed_action is None
    assert result.execution_result == "policy_denied"


def test_invalid_assessment_escalates_without_execution(healthy_evidence: dict):
    decision = policy.evaluate_policy(healthy_evidence, assessment("no_action", status="invalid"))
    result = executor.execute_authorized_action(decision)
    assert decision.policy_decision == "escalated"
    assert decision.authorized_action == "escalate"
    assert result.executed_action == "escalate"
    assert result.execution_result == "escalated"


def test_unknown_action_is_rejected(healthy_evidence: dict):
    decision = policy.evaluate_policy(healthy_evidence, assessment("delete_everything"))
    result = executor.execute_authorized_action(decision)
    assert decision.policy_decision == "escalated"
    assert result.executed_action == "escalate"


def test_command_field_in_assessment_is_rejected(healthy_evidence: dict):
    bad = assessment("no_action")
    bad["command"] = "rm -rf /"
    decision = policy.evaluate_policy(healthy_evidence, bad)
    result = executor.execute_authorized_action(decision)
    assert decision.policy_decision == "escalated"
    assert result.executed_action == "escalate"


def test_executor_refuses_unauthorized_action_directly():
    decision = policy.PolicyDecision(
        proposed_action="restart_application",
        authorized_action=None,
        policy_decision="denied",
        reason="denied",
    )
    result = executor.execute_authorized_action(decision)
    assert result.execution_result == "policy_denied"
    assert result.executed_action is None


def test_verification_is_read_only(healthy_evidence: dict, firing_evidence: dict):
    healthy = verification.verify_recovery(healthy_evidence, "no_action")
    degraded = verification.verify_recovery(firing_evidence, "escalate")
    assert healthy["verification_state"] == "not_applicable"
    assert degraded["verification_state"] == "still_degraded"


def test_denied_remediation_actions(tmp_path: Path, healthy_evidence: dict, firing_evidence: dict):
    for action in ("restart_application", "rollback_application", "scale_application"):
        for evidence in (healthy_evidence, firing_evidence):
            decision = policy.evaluate_policy(evidence, assessment(action))
            result = executor.execute_authorized_action(decision)
            assert decision.policy_decision == "denied"
            assert result.executed_action is None


def test_apply_script_safe_flow_with_test_assessment(healthy_evidence: dict, tmp_path: Path):
    evidence_path = tmp_path / "evidence.json"
    audit_path = tmp_path / "audit.json"
    evidence_path.write_text(json.dumps(healthy_evidence), encoding="utf-8")

    script = Path(__file__).resolve().parent / "scripts" / "apply_incident_action.py"
    result = subprocess.run(
        [
            sys.executable,
            str(script),
            "--evidence-path",
            str(evidence_path),
            "--audit-path",
            str(audit_path),
            "--use-test-assessment",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    assert audit["test_data"] is True
    assert audit["policy_decision"] == "authorized"
    assert audit["executed_action"] == "no_action"


def test_no_subprocess_or_shell_execution():
    with (
        mock.patch("subprocess.run", side_effect=AssertionError("shell commands are not allowed")),
        mock.patch("subprocess.Popen", side_effect=AssertionError("shell commands are not allowed")),
        mock.patch("os.system", side_effect=AssertionError("shell commands are not allowed")),
    ):
        decision = policy.evaluate_policy(
            {"alert": {"state": "inactive"}, "metrics": {}},
            assessment("no_action"),
        )
        executor.execute_authorized_action(decision)


def test_build_test_assessment_is_labeled(healthy_evidence: dict):
    payload = build_test_assessment(healthy_evidence)
    assert payload["test_data"] is True
    assert payload["proposed_action"]["action_type"] == "no_action"
