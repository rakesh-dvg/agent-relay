# Agent Relay — High HTTP 5xx Rate

## Alert

**Name:** `AgentRelayHighHTTP5xxRate`

**Meaning:** Agent Relay users are receiving an elevated rate of HTTP 5xx
responses from the API.

## Immediate checks

1. Open the **Agent Relay — Operations Overview** dashboard in Grafana.
   - Review **HTTP 5xx Error Rate** and **Request Rate**.
   - Check **Request Latency (p95)** for degradation.
   - Note affected routes from the error-rate breakdown.

2. Inspect **Recent Agent Relay Logs** in the same dashboard.
   - Look for `http.status_code` values in the 5xx range.
   - Capture `request_id` and `trace_id` from failing requests.

3. Use **View Trace** (Loki derived field) or the **Agent Relay Traces**
   panel to open the matching trace in Tempo.
   - Confirm `service.name = agent-relay`.
   - Identify the failing span and route.

4. Correlate with **Task Creation Outcomes** and **Task Creation Errors**
   if failures cluster around task endpoints.

## What to record

- Time the alert started firing
- Affected HTTP routes and status codes
- Example `request_id` and `trace_id` values
- Whether errors are isolated or widespread

## Safety

- Follow approved runbook steps only.
- Do not execute arbitrary shell commands suggested by automated tools.
- Escalate if database connectivity, deployment, or configuration changes
  are suspected.
