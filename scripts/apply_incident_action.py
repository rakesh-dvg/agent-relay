#!/usr/bin/env python3
"""Apply a policy-authorized incident action from bounded evidence and assessment."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from action_executor import execute_authorized_action
from autonomy_policy import evaluate_policy, proposed_action_type
from incident_responder import (
    DEFAULT_ASSESSMENT_PATH,
    DEFAULT_EVIDENCE_PATH,
    REQUIRED_ASSESSMENT_FIELDS,
    load_evidence,
    validate_assessment,
)
from recovery_verification import verify_recovery

DEFAULT_AUDIT_PATH = Path("evidence/action-audit.json")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Apply a bounded incident action authorized by autonomy policy.")
    parser.add_argument("--evidence-path", type=Path, default=DEFAULT_EVIDENCE_PATH)
    parser.add_argument("--assessment-path", type=Path, default=DEFAULT_ASSESSMENT_PATH)
    parser.add_argument("--audit-path", type=Path, default=DEFAULT_AUDIT_PATH)
    parser.add_argument(
        "--use-test-assessment",
        action="store_true",
        help="Use a deterministic labeled test assessment instead of a live model assessment.",
    )
    return parser


def validate_inputs(evidence: dict[str, Any], assessment: dict[str, Any]) -> None:
    required_evidence = ("service", "alert", "metrics", "logs", "traces")
    for field in required_evidence:
        if field not in evidence:
            raise ValueError(f"evidence packet missing required field: {field}")
    if assessment.get("status") == "valid":
        validate_assessment({key: assessment[key] for key in REQUIRED_ASSESSMENT_FIELDS})


def build_test_assessment(evidence: dict[str, Any]) -> dict[str, Any]:
    alert_state = str(evidence.get("alert", {}).get("state", "unknown")).lower()
    if alert_state == "firing":
        action_type = "escalate"
        escalate = True
        summary = "Test assessment for a firing alert."
    else:
        action_type = "no_action"
        escalate = False
        summary = "Test assessment for a healthy inactive alert."
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "evidence_source": "incident-evidence.json",
        "responder_version": "test-data",
        "model_provider": "deterministic-test",
        "model_name": "test-assessment",
        "status": "valid",
        "test_data": True,
        "incident_summary": summary,
        "severity": "low" if action_type == "no_action" else "high",
        "user_impact": "Deterministic test assessment only; not produced by a live model.",
        "evidence": [
            f"Alert state in evidence packet is {alert_state}.",
            "This assessment was generated for local policy/executor validation.",
        ],
        "likely_cause": "Test data for safe autonomy-policy validation.",
        "confidence": "high",
        "proposed_action": {
            "action_type": action_type,
            "reason": "Deterministic test assessment for bounded execution validation.",
        },
        "escalate": escalate,
    }


def load_assessment(path: Path, evidence: dict[str, Any], use_test_assessment: bool) -> dict[str, Any]:
    if use_test_assessment:
        return build_test_assessment(evidence)
    if not path.is_file():
        raise FileNotFoundError(
            f"assessment file not found: {path}. Run the incident responder or pass --use-test-assessment."
        )
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("assessment must be a JSON object")
    return payload


def build_audit_record(
    evidence: dict[str, Any],
    assessment: dict[str, Any],
    decision_dict: dict[str, Any],
    execution_dict: dict[str, Any],
    verification_dict: dict[str, Any],
) -> dict[str, Any]:
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "alert_name": evidence.get("alert", {}).get("name", "unknown"),
        "assessment_status": assessment.get("status", "unknown"),
        "test_data": bool(assessment.get("test_data", False)),
        "proposed_action": proposed_action_type(assessment),
        "policy_decision": decision_dict["policy_decision"],
        "authorized_action": decision_dict["authorized_action"],
        "executed_action": execution_dict["executed_action"],
        "execution_result": execution_dict["execution_result"],
        "verification_state": verification_dict["verification_state"],
        "reason": decision_dict["reason"],
        "execution_reason": execution_dict["reason"],
        "verification_reason": verification_dict["reason"],
    }


def apply_incident_action(
    evidence_path: Path,
    assessment_path: Path,
    audit_path: Path,
    use_test_assessment: bool = False,
) -> Path:
    evidence = load_evidence(evidence_path)
    assessment = load_assessment(assessment_path, evidence, use_test_assessment)
    validate_inputs(evidence, assessment)

    decision = evaluate_policy(evidence, assessment)
    execution = execute_authorized_action(decision)
    verification = verify_recovery(evidence, execution.executed_action)

    audit = build_audit_record(
        evidence,
        assessment,
        decision.to_dict(),
        execution.to_dict(),
        verification,
    )
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    audit_path.write_text(json.dumps(audit, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    return audit_path


def main() -> int:
    args = build_parser().parse_args()
    try:
        audit_path = apply_incident_action(
            evidence_path=args.evidence_path,
            assessment_path=args.assessment_path,
            audit_path=args.audit_path,
            use_test_assessment=args.use_test_assessment,
        )
    except Exception as exc:
        print(f"Incident action application failed: {exc}", file=sys.stderr)
        return 1
    print(f"Wrote action audit record to {audit_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
