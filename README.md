# Agent Relay (SQLite starter)

Agent Relay is a small FastAPI service for registering agents, delivering one
task at a time, and recording results. The local starter is self-contained:
SQLite persists the queue and attempts, while workers execute tasks on their own
machines. The included worker deterministically returns `input.upper()`.

## Run it

```bash
uv sync
uv run uvicorn main:app --reload
```

Open <http://127.0.0.1:8000/> for the token-based local dashboard. The default
database is `./agent-relay.db`; set `RELAY_DATABASE_URL` to use another SQLite
file. `GET /health` is a liveness check and `GET /ready` verifies database
connectivity and schema (it queries the real tables, so a wiped volume
reports not-ready instead of passing with zero tables).

Register two identities and send a task:

```bash
alice=$(curl -sS -X POST http://127.0.0.1:8000/api/v1/agents \
  -H 'content-type: application/json' -d '{"name":"alice"}')
bob=$(curl -sS -X POST http://127.0.0.1:8000/api/v1/agents \
  -H 'content-type: application/json' -d '{"name":"uppercase"}')
```

The response contains each agent's secret `token` once. Keep it outside source
control. Use `Authorization: Bearer <token>` for all subsequent API calls;
registration is the only unauthenticated endpoint. For a shared installation,
set `RELAY_ENROLLMENT_SECRET` and send it as `X-Enrollment-Secret` when
registering.

## Run the deterministic worker

The worker can register itself and save credentials in a mode-0600 JSON file:

```bash
uv run python main.py worker \
  --base-url http://127.0.0.1:8000 \
  --name uppercase \
  --credentials ./uppercase-credentials.json \
  --worker-id laptop-1
```

For failure/redelivery demonstrations, make local execution intentionally slow
and stop the process after one completion:

```bash
uv run python main.py worker --credentials ./uppercase-credentials.json \
  --slow-seconds 75 --worker-id slow-laptop
```

The worker heartbeats during long work. Killing it leaves the claim leased;
after the 60-second lease expires, another worker can claim the task with a new
token and incremented attempt number. `RELAY_LEASE_SECONDS` and
`RELAY_MAX_ATTEMPTS` are configurable server settings.

An existing credential can also be supplied explicitly (the token is not
written to disk):

```bash
uv run python main.py worker --agent-id agent_123 --token agt_… --worker-id laptop-2
```

## Storage and delivery behavior

`database.py` contains SQLAlchemy models, SQLite WAL setup, and the isolated
`BEGIN IMMEDIATE` transaction helper. `storage.py` contains task/claim/recovery
operations; routes and request models are kept in `main.py` and `schemas.py`.
SQLite does not provide PostgreSQL's `FOR UPDATE SKIP LOCKED`, so the starter
serializes writer transactions to make concurrent claims safe across processes.
Students can port this storage seam to PostgreSQL later without changing the
HTTP protocol or lifecycle in `SPEC.md`.

Claims are at-least-once and leased for 60 seconds by default. Heartbeats extend
an active lease. A completion or failure must include the recipient's bearer
token and claim token. Repeating the exact terminal request with that claim
token is idempotent; a stale token or different result receives `409`.

## Verify

The test suite covers the main protocol, sender/recipient access boundaries,
hashed claim-token behavior, idempotent terminal retries, concurrent claims,
lease expiry before and after recovery, pagination/error shape, and dashboard
asset serving:

```bash
uv run pytest -q
```

Tests default to a scratch database at `/tmp/agent-relay-test.db` so they
don't reset your dev server's `./agent-relay.db`. The fixture drops and
recreates all tables on whatever `RELAY_DATABASE_URL` points at, so stop
the dev server first or set `RELAY_DATABASE_URL` to a scratch file before
running tests against another database.

This starter intentionally does not include Docker, Kubernetes, CI, external
brokers, an LLM, or a PostgreSQL implementation. Those are deployment and
student-port concerns rather than part of the local relay protocol.

## Observability baseline (Homework 4)

Structured JSON request logs and optional OpenTelemetry tracing are enabled for
the API service.

- Each HTTP request gets an `X-Request-ID` response header. Clients may supply a
  safe `X-Request-ID` header and the relay will reuse it when valid.
- Request logs include method, route, status, duration, `request_id`, and
  `trace_id` when tracing is active. Authorization headers, tokens, and task
  bodies are not logged.
- OpenTelemetry instruments FastAPI HTTP requests and adds an application span
  for `POST /api/v1/tasks` named `agent_relay.create_task`.
- Telemetry is optional. Tests and local development disable export by default
  with `OTEL_SDK_DISABLED=true`. To export traces when a collector is available,
  unset that variable and set `OTEL_EXPORTER_OTLP_ENDPOINT`.

### Application metrics (Homework 4)

Agent Relay exposes Prometheus-format metrics at `GET /metrics` on the API port
(`8000` by default). No authentication is required for local development.

Collected metrics:

| Metric | Type | Labels | Purpose |
| --- | --- | --- | --- |
| `agent_relay_http_requests_total` | Counter | `method`, `route`, `status_code` | HTTP request volume |
| `agent_relay_http_request_duration_seconds` | Histogram | `method`, `route` | HTTP latency |
| `agent_relay_task_created_total` | Counter | `status` | Successful task creation outcomes |
| `agent_relay_task_errors_total` | Counter | `error_type` | Task creation failures |

HTTP metrics use normalized FastAPI route templates (for example
`/api/v1/tasks/{task_id}`) rather than raw URLs, so labels stay bounded.
Task error labels are limited to `validation`, `not_found`, `unauthorized`,
`conflict`, `internal`, and `unknown`. Tokens, request IDs, task IDs, and
request bodies are never used as metric labels.

When the observability stack is running with the `compose.observability.yaml`
overlay, Prometheus scrapes `http://app:8000/metrics` automatically. On the
host, the same metrics are available at `http://127.0.0.1:8000/metrics`.
Traces continue to flow through the OpenTelemetry Collector.

### Application logs in Loki (Homework 4)

Agent Relay continues to write structured JSON logs to stdout/stderr. Promtail
reads Docker container logs from the runtime (via a read-only Docker socket
mount), forwards Agent Relay log lines to Loki, and keeps high-cardinality
fields such as `request_id` and `trace_id` in the log body rather than Loki
stream labels. Search logs in Grafana using the Loki data source, for example:

```logql
{container=~"agent-relay-app.*"} |= "http request completed"
```

## Local observability stack (Homework 4)

The application stack and observability stack are separate Compose setups:

| Stack | File | Purpose |
| --- | --- | --- |
| Application | `compose.yaml` | Agent Relay API + PostgreSQL on port `8000` |
| Observability | `observability/compose.yaml` | Collector + Prometheus + Loki + Tempo + Grafana |

### Start the observability stack

```bash
docker compose -f observability/compose.yaml up -d
```

Services and local ports:

| Service | Port | URL |
| --- | --- | --- |
| Grafana | 3000 | http://127.0.0.1:3000 |
| Prometheus | 9090 | http://127.0.0.1:9090 |
| Loki | 3100 | http://127.0.0.1:3100 |
| Tempo | 3200 | http://127.0.0.1:3200 |
| OpenTelemetry Collector (OTLP/HTTP) | 4318 | http://127.0.0.1:4318 |
| OpenTelemetry Collector (health) | 13133 | http://127.0.0.1:13133 |
| Promtail | 9080 | internal log collector |

Grafana starts with provisioned data sources for Prometheus, Loki, and Tempo.
Promtail ships Agent Relay container logs to Loki.
Anonymous admin access is enabled for local development only.

### Grafana dashboard (Homework 4)

Open Grafana locally at [http://127.0.0.1:3000](http://127.0.0.1:3000). The
provisioned dashboard **Agent Relay — Operations Overview** combines metrics
(Prometheus), logs (Loki), and traces (Tempo) for investigating user-impacting
incidents. Log lines include a **View Trace** link when `trace_id` is present,
using Grafana's Loki derived-field linking to Tempo.

### Connect Agent Relay to the collector

**On the host (uvicorn):**

```bash
export OTEL_SDK_DISABLED=false
export OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318
uv run uvicorn main:app --reload
```

**In Docker with PostgreSQL:**

```bash
docker compose -f observability/compose.yaml up -d
docker compose -f compose.yaml -f compose.observability.yaml up -d
```

The optional overlay `compose.observability.yaml` joins the app container to the
shared `agent-relay-observability` network and sets
`OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318`.

Agent Relay works normally without the observability stack. If the collector is
unavailable, leave `OTEL_SDK_DISABLED=true` or omit `OTEL_EXPORTER_OTLP_ENDPOINT`.

### Stop the observability stack

```bash
docker compose -f observability/compose.yaml down
```

Add `-v` to remove observability volumes.

### Bounded incident evidence (Homework 4)

The read-only collector gathers a fixed, allowlisted evidence packet from the
existing observability stack:

```bash
uv run python scripts/collect_incident_evidence.py
```

Output path: `evidence/incident-evidence.json`

It queries only:

| Source | Fixed evidence |
| --- | --- |
| Prometheus | `AgentRelayHighHTTP5xxRate` alert state, HTTP request rate, HTTP 5xx rate/ratio, task creation metrics |
| Loki | Recent Agent Relay structured logs |
| Tempo | Recent Agent Relay traces |

Queries are defined in code. The collector does **not** accept arbitrary
PromQL, LogQL, shell commands, or URL overrides from command-line arguments.
Service URLs are configured only through `PROMETHEUS_URL`, `LOKI_URL`, and
`TEMPO_URL`.

The collector is read-only, applies strict timeouts/limits, and redacts tokens,
passwords, credentials, and task input before writing JSON. A future headless AI
responder will receive this bounded evidence packet rather than unrestricted
system access.

### Headless incident investigator (Homework 4)

The headless responder reads the bounded evidence packet and writes a structured
assessment to `evidence/incident-assessment.json`:

```bash
uv run python scripts/collect_incident_evidence.py
uv run python scripts/run_incident_responder.py
```

Configure an OpenAI-compatible model with environment variables such as
`INCIDENT_AI_PROVIDER=openai` and `INCIDENT_AI_API_KEY` (or `OPENAI_API_KEY`).

The investigator:

- analyzes **only** the supplied evidence JSON
- returns a structured assessment with bounded `proposed_action.action_type`
  values (`restart_application`, `rollback_application`, `scale_application`,
  `no_action`, `escalate`)
- rejects invalid model output, including unsupported actions or forbidden
  command-like fields
- does **not** execute remediation, shell commands, observability queries, or
  configuration changes

Authorization and execution happen outside the model in later steps.

### Autonomy policy and bounded execution (Homework 4)

The AI proposes an action in `evidence/incident-assessment.json`. A separate
policy layer authorizes it, and a bounded executor performs only approved work:

```bash
uv run python scripts/collect_incident_evidence.py
uv run python scripts/run_incident_responder.py
uv run python scripts/apply_incident_action.py
```

For local validation without a live model assessment:

```bash
uv run python scripts/apply_incident_action.py --use-test-assessment
```

Flow:

1. AI assessment proposes a bounded action type.
2. `autonomy_policy.py` authorizes or denies it.
3. `action_executor.py` executes only policy-authorized actions.
4. `recovery_verification.py` performs read-only recovery checks from evidence.
5. `evidence/action-audit.json` records proposal, policy decision, execution,
   and verification.

Currently executable actions: `no_action`, `escalate`.

`restart_application`, `rollback_application`, and `scale_application` may be
proposed by the AI but are policy-denied and never executed in this step.

### Deterministic security scanning (Homework 4)

Semgrep provides deterministic, rule-based security checks that are independent
of the AI incident responder. The model does not decide whether code is safe;
Semgrep applies fixed rules to application source and scripts.

Install Semgrep separately if needed:

```bash
pip install semgrep
```

Run the repository scan:

```bash
semgrep --config .semgrep/agent-relay.yml .
```

Recommended exclusions for local runs:

```bash
semgrep --config .semgrep/agent-relay.yml . \
  --exclude .venv \
  --exclude __pycache__ \
  --exclude evidence \
  --exclude observability
```

Custom rules in `.semgrep/agent-relay.yml` check for:

| Rule | Detects |
| --- | --- |
| `agent-relay-subprocess-shell-true` | `subprocess.*(..., shell=True, ...)` |
| `agent-relay-os-system` | `os.system(...)` |
| `agent-relay-eval-exec` | `eval(...)` or `exec(...)` |
| `agent-relay-hardcoded-secret-assignment` | suspicious hardcoded secret/password/token assignments |

A clean scan should report **no findings** in the current application code.
The scanner configuration is validated in `test_semgrep_config.py`.

### Current limitations

- Traces exported from Agent Relay are visible in Tempo through Grafana.
- Prometheus scrapes the OpenTelemetry Collector on port `8889` and Agent Relay
  application metrics at `app:8000/metrics` when the app runs with the
  observability overlay.
- Agent Relay logs are collected from Docker container stdout by Promtail and
  stored in Loki. Alert notifications/Alertmanager routing are not configured
  yet.
