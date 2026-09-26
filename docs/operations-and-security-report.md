# Agent Relay — Operations and Security Report (Homework 4)

This report documents the Homework 4 incident-response loop implemented in this
repository. It distinguishes three categories of evidence:

| Category | Meaning |
| --- | --- |
| **Implemented capability** | Code, configuration, and scripts present in the repo |
| **Test / validation evidence** | Deterministic test data, pytest results, and local scan output |
| **Real incident evidence** | Not available — no production outage was observed or remediated |

**Application version (from `pyproject.toml`):** `0.1.0`

---

## 1. Deployed Version and User Impact

### Implemented capability

Agent Relay is a FastAPI task-relay API instrumented for Homework 4 with:

- **Structured JSON logs** (`telemetry.py` — `JsonFormatter`)
- **OpenTelemetry** traces exported via OTLP HTTP to the observability collector
- **Prometheus metrics** at `/metrics` (`telemetry_metrics.py`)
- **Loki** log storage via Promtail scraping Docker container stdout
- **Tempo** distributed trace storage
- **Grafana dashboard:** *Agent Relay — Operations Overview*
  (`observability/grafana/provisioning/dashboards/agent-relay-operations-overview.json`)

The observability stack runs separately from the application stack
(`observability/compose.yaml` plus optional `compose.observability.yaml` overlay).

### User-impact alert

Prometheus alert **`AgentRelayHighHTTP5xxRate`**
(`observability/prometheus-alerts.yaml`):

- **Condition:** HTTP 5xx ratio ≥ **5%** sustained for **5 minutes**
- **Severity:** critical
- **User impact (when firing):** users receive server errors from the Agent Relay API
- **Runbook:** `docs/runbooks/agent-relay-high-5xx.md`

### What this report does NOT claim

- No real production deployment version beyond repository metadata (`0.1.0`) is asserted.
- No real user outage, user count, or production impact occurred during validation.
- Alertmanager notification routing is not configured (documented limitation in `README.md`).

---

## 2. Alert and Evidence

### Implemented capability

Bounded, read-only evidence collection is implemented in `incident_evidence.py`
and invoked via:

```bash
uv run python scripts/collect_incident_evidence.py
```

Output: `evidence/incident-evidence.json`

### Allowlisted queries (fixed in code — not user-supplied)

| Source | Evidence collected |
| --- | --- |
| **Prometheus** | Alert state for `AgentRelayHighHTTP5xxRate`; HTTP request rate; HTTP 5xx rate; HTTP 5xx ratio; task creation rate by status; task error rate by type |
| **Loki** | `{container=~"agent-relay-app.*"} \|= "http request completed"` |
| **Tempo** | `service.name=agent-relay` |

### Collection limits (`incident_evidence.py`)

| Limit | Value |
| --- | --- |
| HTTP timeout | 5 seconds |
| Max response bytes | 256,000 |
| Max log entries | 50 |
| Max traces | 10 |
| Lookback window | 900 seconds (15 minutes) |

### Safety controls

- Arbitrary PromQL, LogQL, shell commands, and URL overrides from CLI arguments are **rejected**.
- Service URLs are configurable only via `PROMETHEUS_URL`, `LOKI_URL`, and `TEMPO_URL`.
- Sensitive keys and values (tokens, passwords, credentials, task input, etc.) are **redacted** before writing JSON.

### Validation evidence on disk

The repository contains a collected evidence packet at
`evidence/incident-evidence.json` (`generated_at`: `2026-09-26T02:26:18Z`).

From that packet:

- **Alert state:** `inactive` (not firing)
- **Metrics present:** HTTP request rate, task creation metrics; 5xx rate/ratio samples empty in this snapshot
- **Logs:** structured JSON log lines (e.g. `http request completed` for `/metrics`)
- **Traces:** bounded Agent Relay traces (e.g. `GET /metrics`)
- **Version field:** `0.1.0`
- **Collection limits recorded** in the JSON under `collection_limits`

This is **observability-stack validation evidence**, not proof that the alert fired in production.

---

## 3. Model / Configuration and AI Assessment

### Implemented capability

The headless AI investigator is implemented in `incident_responder.py` and invoked via:

```bash
uv run python scripts/run_incident_responder.py
```

Configuration (environment variables):

- `INCIDENT_AI_PROVIDER` (default: `openai`)
- `INCIDENT_AI_API_KEY` or `OPENAI_API_KEY`
- `INCIDENT_AI_MODEL` / `OPENAI_MODEL` (default: `gpt-4o-mini`)
- `INCIDENT_AI_BASE_URL` / `OPENAI_BASE_URL`

Output path: `evidence/incident-assessment.json`

### Investigator constraints

- Reads **only** the bounded evidence packet (`evidence/incident-evidence.json`).
- Does **not** directly query Prometheus, Loki, Tempo, or other observability systems.
- Does **not** execute commands, shell scripts, or infrastructure changes.
- Returns a structured assessment with bounded `proposed_action.action_type` vocabulary:
  - `no_action`
  - `escalate`
  - `restart_application`
  - `rollback_application`
  - `scale_application`
- Rejects invalid model output, including unsupported actions or forbidden command-like fields (`command`, `shell`, `exec`, `script`, `exec_command`).
- **Model proposals are NOT automatically executable** — authorization and execution happen in separate policy and executor layers.

### Validation status

| Item | Status |
| --- | --- |
| Responder code and validation tests | Implemented and covered by `test_incident_responder.py` |
| Live model assessment (`incident-assessment.json`) | **Not produced** — no API key was configured for a live run |
| Deterministic test assessment | Available via `--use-test-assessment` in `scripts/apply_incident_action.py` |

---

## 4. Autonomy Policy Decision

### Implemented capability

Policy evaluation is implemented in `autonomy_policy.py` (`evaluate_policy`).

### Executable allowlist

Only these actions may execute automatically:

| Action | Policy status |
| --- | --- |
| `no_action` | Authorized when assessment is valid and policy conditions are met |
| `escalate` | Authorized when assessment is valid and policy conditions are met |
| `restart_application` | **Policy-denied** |
| `rollback_application` | **Policy-denied** |
| `scale_application` | **Policy-denied** |

### Escalation triggers

The policy escalates (maps to `escalate`) when:

- Assessment status is not `valid`
- Proposed action is unknown / not in the approved vocabulary
- Assessment contains forbidden command-like fields

The policy denies (no execution) when:

- Proposed remediation action is not in the executable allowlist
- Alert is inactive and a remediation action is proposed

### Executor boundary

`action_executor.py` accepts a **`PolicyDecision`**, not raw model output. Unauthorized or denied actions are refused before any mutation.

Policy behavior is covered by `test_autonomy_execution.py`.

---

## 5. Command / Action Executed

### Implemented capability

Bounded execution is implemented in `action_executor.py` and orchestrated by:

```bash
uv run python scripts/apply_incident_action.py
```

For local validation without a live model:

```bash
uv run python scripts/apply_incident_action.py --use-test-assessment
```

### Executor behavior

| Authorized action | Behavior |
| --- | --- |
| `no_action` | Completes successfully; **no infrastructure mutation** |
| `escalate` | Records structured escalation result; **no infrastructure mutation** |
| Unauthorized remediation (`restart_application`, `rollback_application`, `scale_application`) | **Not executed** — policy denies and executor refuses |

The bounded executor has **no** `subprocess`, `os.system`, shell, `eval`, or `exec` execution path.

### Audit record

Each run writes `evidence/action-audit.json`, separating:

- **Proposed action** (from assessment)
- **Policy decision** (`authorized`, `denied`, or `escalated`)
- **Authorized action**
- **Executed action**
- **Execution result**
- **Verification state**

---

## 6. Recovery Verification

### Implemented capability

Read-only recovery checks are implemented in `recovery_verification.py`
(`verify_recovery`).

Checks use the bounded evidence packet only:

- Alert state
- HTTP 5xx ratio (threshold reference: 5%)
- HTTP request rate

### Verification statuses

| Status | Meaning |
| --- | --- |
| `recovered` | Alert inactive and 5xx ratio below threshold |
| `still_degraded` | Alert firing or 5xx ratio still elevated |
| `not_applicable` | No remediation executed and alert not firing |
| `verification_failed` | Recovery could not be determined from available evidence |

Recovery verification does not mutate infrastructure.

---

## 7. Escalation Path

When evidence, assessment, or policy does **not** authorize an automatic action,
**escalation is the safe path**.

Concrete escalation scenarios implemented in policy:

- Invalid or malformed assessment → escalate
- Unknown proposed action → escalate
- Forbidden command-like fields in assessment → escalate
- Policy-denied remediation proposals → refused; human review required

Human operators follow `docs/runbooks/agent-relay-high-5xx.md`:

1. Open the Grafana *Agent Relay — Operations Overview* dashboard
2. Inspect recent Loki logs and Tempo traces
3. Record affected routes, status codes, `request_id`, and `trace_id` values
4. Do not execute arbitrary shell commands suggested by automated tools

### Current limitations

- **Automatic restart, rollback, and scale are NOT enabled** in this repository step.
- **Live AI incident assessment was not performed** without an API key.
- **No real production incident recovery** occurred or is claimed here.

---

## 8. Deterministic Security Scanning

Semgrep provides rule-based security checks independent of the AI investigator.

### Configuration

- Rules file: `.semgrep/agent-relay.yml`
- **4 deterministic rules:**

| Rule ID | Detects |
| --- | --- |
| `agent-relay-subprocess-shell-true` | `subprocess.*(..., shell=True, ...)` |
| `agent-relay-os-system` | `os.system(...)` |
| `agent-relay-eval-exec` | `eval(...)` or `exec(...)` |
| `agent-relay-hardcoded-secret-assignment` | suspicious hardcoded secret/password/token assignments |

### Scan command (documented in `README.md`)

```bash
semgrep --config .semgrep/agent-relay.yml . \
  --exclude .venv \
  --exclude __pycache__ \
  --exclude evidence \
  --exclude observability
```

### Latest validation scan results

| Metric | Result |
| --- | --- |
| Exit code | `0` |
| Rules run | 4 |
| Targets scanned | 23 |
| Findings | **2** (both blocking) |

**Findings location:** `test_observability.py` only

| Line | Finding | Explanation |
| --- | --- | --- |
| 94 | `secret_input = "top-secret-task-input-xyz"` | Intentional test string for log redaction validation |
| 185 | `secret_input = "super-secret-task-input"` | Intentional test string for log redaction validation |

These are **not real credentials**. They exercise the hardcoded-secret rule against
secret-like variable names used to verify that sensitive values are redacted in logs.

**No production-code findings** were reported in the latest scan.

Configuration and rule detection are validated in `test_semgrep_config.py`.

---

## 9. Validation / Testing Results

### Latest pytest result

```
44 passed, 1 warning in ~9s
```

Command: `uv run pytest -q`

The warning is a Starlette/FastAPI deprecation notice for `httpx` vs `httpx2` in
the test client; it does not indicate a test failure.

### Test coverage by area

| Module / area | Test file |
| --- | --- |
| Core API and storage | `test_agent_relay.py` |
| Structured logging and OpenTelemetry | `test_observability.py` |
| Bounded evidence collection | `test_incident_evidence.py` |
| Headless AI investigator | `test_incident_responder.py` |
| Autonomy policy, executor, recovery | `test_autonomy_execution.py` |
| Semgrep configuration | `test_semgrep_config.py` |

### Test-environment note (not a production change)

During validation on Windows, pytest collection failed when test modules used
Unix-only scratch database paths (`sqlite:////tmp/...`) because `/tmp` does not
exist on Windows.

**Fix (test-only):** `test_agent_relay.py` and `test_observability.py` now default
to scratch SQLite files under the OS temp directory via `tempfile.gettempdir()`.
Production database behavior in `database.py` was not changed.

---

## Safe-Flow Demonstration (TEST DATA)

> **This section describes deterministic test validation, not a real production incident.**

The repository includes a safe end-to-end autonomy flow validated with
`--use-test-assessment` against the collected evidence packet (alert state:
`inactive`).

Audit record on disk: `evidence/action-audit.json`

| Field | Value |
| --- | --- |
| `test_data` | `true` |
| `assessment_status` | `valid` |
| `proposed_action` | `no_action` |
| `policy_decision` | `authorized` |
| `authorized_action` | `no_action` |
| `executed_action` | `no_action` |
| `execution_result` | `success` |
| `verification_state` | `not_applicable` |
| `execution_reason` | No infrastructure mutation was required |
| `verification_reason` | No remediation was executed and the alert is not firing |

**No mutation occurred.** No restart, rollback, scale, or shell command was executed.

To reproduce locally (requires observability stack for evidence collection; test
assessment does not require an API key):

```bash
uv run python scripts/collect_incident_evidence.py
uv run python scripts/apply_incident_action.py --use-test-assessment
```

---

## Summary

Homework 4 implements a bounded incident-response loop for Agent Relay:

1. **Observe** — structured logs, metrics, traces, Grafana dashboard, and a user-impact 5xx alert
2. **Collect** — read-only, allowlisted, redacted evidence packet
3. **Assess** — headless AI investigator (live run optional; not performed here)
4. **Authorize** — autonomy policy with a narrow executable allowlist (`no_action`, `escalate`)
5. **Execute** — bounded executor with audit trail (`evidence/action-audit.json`)
6. **Verify** — read-only recovery checks from evidence
7. **Escalate** — safe default when automation is not authorized
8. **Scan** — deterministic Semgrep rules with clean production-code scan results
9. **Test** — 44 passing pytest tests validating the full loop

Real production incident recovery is **not claimed**. The documented safe flow uses
labeled test data to demonstrate that policy, execution, and verification work
correctly without infrastructure mutation.
