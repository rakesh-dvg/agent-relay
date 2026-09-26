#!/usr/bin/env python3
"""Collect bounded, read-only incident evidence from the observability stack."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from incident_evidence import DEFAULT_OUTPUT_PATH, write_evidence_packet


def main() -> int:
    if len(sys.argv) > 1:
        print(
            "This collector does not accept command-line query arguments.",
            file=sys.stderr,
        )
        print(
            "Use fixed allowlisted queries with optional service URLs via "
            "PROMETHEUS_URL, LOKI_URL, and TEMPO_URL.",
            file=sys.stderr,
        )
        return 2
    output = write_evidence_packet(project_root=ROOT)
    print(f"Wrote incident evidence packet to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
