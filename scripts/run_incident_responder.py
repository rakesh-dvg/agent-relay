#!/usr/bin/env python3
"""Run the headless Agent Relay incident investigator."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from incident_responder import (
    DEFAULT_EVIDENCE_PATH,
    InvalidAssessmentError,
    ResponderNotConfiguredError,
    run_incident_responder,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze bounded incident evidence with a headless AI responder.")
    parser.add_argument(
        "--evidence-path",
        type=Path,
        default=DEFAULT_EVIDENCE_PATH,
        help="Path to the bounded evidence packet JSON (for tests/local use).",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        output = run_incident_responder(evidence_path=args.evidence_path, project_root=ROOT)
    except ResponderNotConfiguredError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except InvalidAssessmentError as exc:
        print(f"Invalid model assessment: {exc}", file=sys.stderr)
        return 3
    except Exception as exc:
        print(f"Incident responder failed: {exc}", file=sys.stderr)
        return 1
    print(f"Wrote incident assessment to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
