---
id: 006-health-readiness-shutdown
unit: 001-proxy-core
intent: 006-sidecar-proxy-enforcement
status: draft
priority: must
created: 2026-04-05T12:00:00Z
assigned_bolt: null
implemented: false
---

# Story: 006-health-readiness-shutdown

## User Story

**As an** operator
**I want** health and readiness endpoints plus graceful shutdown
**So that** the Sidecar integrates correctly with container orchestrators and monitoring systems, and in-flight requests are not abruptly terminated during deployments

## Acceptance Criteria

- [ ] **Given** the Sidecar is running, **When** a client sends `GET /healthz`, **Then** the response is `200 OK` with a simple JSON body (e.g., `{"status": "healthy"}`)
- [ ] **Given** the Sidecar has completed initialization (policy bundle loaded, CA keypair available, all configured credential providers initialized), **When** a client sends `GET /readyz`, **Then** the response is `200 OK` with a JSON body indicating readiness (e.g., `{"status": "ready", "checks": {"policy_bundle": true, "ca_keypair": true, "credential_providers": true}}`)
- [ ] **Given** the Sidecar is still initializing (e.g., policy bundle not yet loaded), **When** a client sends `GET /readyz`, **Then** the response is `503 Service Unavailable` with a JSON body indicating which checks failed
- [ ] **Given** the Sidecar receives a `SIGTERM` signal, **When** graceful shutdown begins, **Then** it immediately stops accepting new connections
- [ ] **Given** in-flight requests exist when `SIGTERM` is received, **When** the drain period is active, **Then** all in-flight requests are allowed to complete up to the configurable drain timeout (default 30 seconds)
- [ ] **Given** the drain timeout expires with in-flight requests still active, **When** the timeout fires, **Then** remaining connections are forcefully terminated and the process exits
- [ ] **Given** pending audit events exist when shutdown begins, **When** the drain completes, **Then** all buffered audit events are flushed to configured sinks before the process exits

## Technical Notes

- Health and readiness endpoints should run on the same listen address as the proxy or on a separate admin port (configurable); running on the same port is simpler but means health checks go through the proxy path
- Consider using a dedicated Pingora service (or a separate lightweight HTTP server like `axum` or `hyper`) for admin endpoints to avoid interference with proxy traffic
- Readiness checks should be implemented as a pluggable set of `ReadinessCheck` functions so that other units can register their own checks (e.g., policy source registers its "bundle loaded" check)
- Graceful shutdown sequence:
  1. Receive SIGTERM
  2. Set readiness to `false` (subsequent `/readyz` returns 503)
  3. Stop accepting new connections on the proxy listener
  4. Wait for in-flight requests to complete (up to drain timeout)
  5. Flush pending audit events to all sinks
  6. Exit with status code 0
- Use `tokio::signal::unix::signal(SignalKind::terminate())` for SIGTERM handling
- Drain timeout should come from configuration (story 005), default 30 seconds
- The `/healthz` endpoint should remain available during the drain period (Kubernetes liveness probes must still work during graceful shutdown)
- Consider also handling `SIGINT` (Ctrl+C) with the same graceful shutdown logic for local development

## Dependencies

### Requires

- 005-config-and-startup (drain timeout from configuration)
- 003-ca-keypair-management (readiness check: CA keypair available)

### Enables

- Container orchestrator integration (Kubernetes liveness/readiness probes)
- Zero-downtime deployments (rolling updates rely on readiness + graceful drain)
- Audit completeness (flush guarantees no silent event loss during shutdown)

## Edge Cases

| Scenario | Expected Behavior |
| -------- | ----------------- |
| `/readyz` called before any initialization | Returns 503 with all checks failed |
| Policy bundle becomes stale (TTL expires) after initial readiness | `/readyz` returns 503; the Sidecar continues serving but in fail-closed mode (DENY all) |
| SIGTERM received during startup (before readiness) | Skip drain (no in-flight requests); flush any buffered audit events; exit promptly |
| Two SIGTERM signals in rapid succession | Second signal ignored; shutdown already in progress |
| SIGKILL received during drain | Process killed immediately by OS; no cleanup possible; this is expected behavior |
| Drain timeout set to 0 | Immediately terminate all connections after SIGTERM; no drain period |
| Health check from orchestrator during drain period | `/healthz` returns 200 (process is alive); `/readyz` returns 503 (not ready for new traffic) |
| Audit flush fails during shutdown (sink unavailable) | Log the error; do not block shutdown indefinitely; exit after a brief flush timeout (e.g., 5 seconds) |
| No in-flight requests at SIGTERM | Skip drain wait; proceed directly to audit flush and exit |

## Out of Scope

- Prometheus `/metrics` endpoint (unit 006-audit-observability, story 004-prometheus-metrics)
- Custom health check extensions (e.g., deep health checks to upstream targets)
- Readiness dependencies on external systems (e.g., Authority reachability)
- Pre-stop hooks or lifecycle scripts (operator's responsibility in orchestrator config)
- SIGHUP-triggered configuration reload
