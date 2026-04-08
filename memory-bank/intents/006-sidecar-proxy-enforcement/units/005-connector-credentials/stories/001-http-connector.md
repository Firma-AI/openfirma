---
id: 001-http-connector
unit: 005-connector-credentials
intent: 006-sidecar-proxy-enforcement
status: draft
priority: must
created: 2026-04-05T12:00:00Z
assigned_bolt: null
implemented: false
---

# Story: 001-http-connector

## User Story

**As the** Sidecar
**I want** a generic HTTP connector that translates authorized ExecutionEnvelopes into outbound requests with connection pooling and timeouts
**So that** authorized agent calls reach their targets reliably

## Acceptance Criteria

- [ ] **Given** an authorized ExecutionEnvelope and its derived transport-ready execution view, **When** the connector dispatches the request, **Then** the outbound HTTP request contains the correct method, URL, headers, and body as specified by the execution view
- [ ] **Given** multiple sequential requests to the same target host, **When** the connector dispatches them, **Then** connections are reused from a pool with a configurable pool size per target host
- [ ] **Given** a per-target timeout configuration (default 30s), **When** the target does not respond within the configured timeout, **Then** the connector returns `CONNECTOR_TIMEOUT` to the caller without blocking indefinitely
- [ ] **Given** any dispatched request, **When** the target responds (or times out), **Then** the ConnectorResponse includes status code, response headers, response body, and latency (in microseconds) for downstream audit
- [ ] **Given** an authorized ExecutionEnvelope with intent, capability, and metadata fields, **When** the connector processes the envelope, **Then** the connector does not inspect or modify those fields (FEP §9 Connector Boundary Rules)
- [ ] **Given** a target host with no explicit pool size or timeout configured, **When** the connector dispatches to that host, **Then** sensible defaults are applied (default pool size, 30s timeout)

## Technical Notes

- Use `hyper` or `reqwest` as the underlying HTTP client; both provide built-in connection pooling
- Connection pool configuration should be per-host, specified in the TOML config under a `[connectors]` or `[targets]` section
- The connector receives a `TransportView` (derived from the immutable ExecutionEnvelope by the credential injection layer, story 003) — it does not interact with the raw ExecutionEnvelope directly
- ConnectorResponse is a new type containing: `status_code: u16`, `headers: HeaderMap`, `body: Bytes`, `latency_us: u64`
- Timeout enforcement should use `tokio::time::timeout` wrapping the HTTP client call
- The connector is invoked only after Stage 2 ALLOW — it never makes authorization decisions
- For HTTPS targets, the connector uses the system CA bundle (or a configurable CA bundle) for outbound TLS — this is separate from the MITM TLS on the agent-facing side

## Dependencies

### Requires

- 003-credential-injection (provides the TransportView with injected credentials)

### Enables

- 001-proxy-core (proxy returns the ConnectorResponse to the agent after dispatch)
- 006-audit-observability (ConnectorResponse latency included in audit events)

## Edge Cases

| Scenario | Expected Behavior |
| -------- | ----------------- |
| Target returns an HTTP error (4xx, 5xx) | ConnectorResponse returned with the error status code; no connector-level retry in V1 |
| Target closes connection mid-response | ConnectorResponse with an error; connection removed from pool; reported as connector error |
| Target host DNS resolution fails | Connector returns an error immediately; no retry; agent receives 502 or equivalent |
| Connection pool exhausted for a target host | Request queued until a connection becomes available or timeout fires (whichever comes first) |
| Request body is empty (GET, HEAD, DELETE) | Dispatched normally with no body; no error |
| Very large response body (>100 MB) | Streamed back without full buffering in the connector; configurable response size limit |
| Target uses self-signed or untrusted TLS certificate | Connection fails; connector returns TLS error; no silent downgrade to HTTP |
| Concurrent requests to different target hosts | Each host has its own independent connection pool; no cross-host interference |

## Out of Scope

- Retry policies (no automatic retries in V1; future enhancement)
- Circuit breaker patterns (future enhancement)
- Non-HTTP connectors (gRPC, WebSocket, database wire protocols)
- Credential resolution and injection (story 002 and 003)
- Enforcement decisions (owned by 002-enforcement-pipeline)
- Audit event emission (unit 006-audit-observability)
