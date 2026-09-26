"""Validation for the deterministic Semgrep security configuration."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent
SEMGREP_CONFIG = REPO_ROOT / ".semgrep" / "agent-relay.yml"
EXPECTED_RULE_IDS = {
    "agent-relay-subprocess-shell-true",
    "agent-relay-os-system",
    "agent-relay-eval-exec",
    "agent-relay-hardcoded-secret-assignment",
}


def semgrep_available() -> bool:
    return shutil.which("semgrep") is not None


def _normalize_check_id(check_id: str) -> str:
    prefix = "semgrep."
    return check_id[len(prefix) :] if check_id.startswith(prefix) else check_id


def test_semgrep_config_exists_and_lists_expected_rules():
    assert SEMGREP_CONFIG.is_file()
    contents = SEMGREP_CONFIG.read_text(encoding="utf-8")
    for rule_id in EXPECTED_RULE_IDS:
        assert f"id: {rule_id}" in contents


@pytest.mark.skipif(not semgrep_available(), reason="semgrep is not installed")
def test_semgrep_config_validates_with_cli():
    result = subprocess.run(
        ["semgrep", "--validate", "--config", str(SEMGREP_CONFIG)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr or result.stdout


@pytest.mark.skipif(not semgrep_available(), reason="semgrep is not installed")
def test_semgrep_rules_detect_sample_violations(tmp_path: Path):
    sample = tmp_path / "sample_violations.py"
    sample.write_text(
        "import os\nimport subprocess\n\n"
        'os.system("echo unsafe")\n'
        "subprocess.run('echo unsafe', shell=True)\n"
        'eval("1 + 1")\n'
        'api_key = "hardcoded-secret-value"\n',
        encoding="utf-8",
    )
    result = subprocess.run(
        [
            "semgrep",
            "--config",
            str(SEMGREP_CONFIG),
            "--quiet",
            "--json",
            str(sample),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    rule_ids = {
        _normalize_check_id(finding["check_id"])
        for finding in payload.get("results", [])
    }
    assert EXPECTED_RULE_IDS <= rule_ids


def test_repository_scan_command_is_documented_in_readme():
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert "semgrep --config .semgrep/agent-relay.yml ." in readme


def test_scan_excludes_are_documented_in_readme():
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    for excluded in (".venv", "__pycache__", "evidence", "observability"):
        assert excluded in readme
