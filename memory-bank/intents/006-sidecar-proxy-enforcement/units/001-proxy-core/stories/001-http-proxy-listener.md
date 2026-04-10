---
id: 001-http-proxy-listener
unit: 001-proxy-core
intent: 006-sidecar-proxy-enforcement
status: draft
priority: must
created: 2026-04-05T12:00:00Z
assigned_bolt: null
implemented: false
---

# Story: 001-http-proxy-listener

## User Story

**As an** AI agent runtime
**I want** all my outbound HTTP requests to be transparently intercepted by the Sidecar proxy
**So that** every call can be evaluated by the enforcement pipeline before reaching the target

## Acceptance Criteria

- [ ] **Given** the Sidecar is started with default configuration, **When** an agent sends a plain HTTP request through the proxy, **Then** Pingora intercepts the request and the full request (method, headers, body, URL) is available for downstream processing
- [ ] **Given** a configurable listen address and port (default `:8080`), **When** the Sidecar starts, **Then** it binds to the configured address and accepts incoming HTTP proxy connections
- [ ] **Given** an agent with `HTTP_PROXY=http://localhost:8080`, **When** the agent makes an HTTP GET request to any target, **Then** the proxy receives the request with the complete URL (not just the path)
- [ ] **Given** an agent sends an HTTP POST with a JSON body, **When** the proxy intercepts the request, **Then** the full body is buffered and available for inspection before forwarding
- [ ] **Given** the Pingora `ProxyHttp` trait implementation, **When** a request arrives, **Then** the `request_filter` hook fires with the complete request context before any upstream connection is made
- [ ] **Given** multiple concurrent HTTP requests, **When** they arrive at the proxy simultaneously, **Then** all are intercepted independently without blocking each other

## Technical Notes

- Implement the Pingora `ProxyHttp` trait on a `FirmaSidecar` struct (or similar)
- Use `request_filter` as the primary hook for pre-enforcement request capture
- Request body must be fully buffered before enforcement can evaluate it; configure Pingora's body buffering accordingly
- The proxy operates as a forward proxy (not reverse proxy) — the agent's request URL contains the full target address
- Listen address should default to `0.0.0.0:8080` but be overridable via config and CLI
- This story covers only plain HTTP interception; HTTPS CONNECT is handled in story 002
- The proxy does not make enforcement decisions itself — it captures the request and delegates to the enforcement pipeline (unit 002)

## Dependencies

### Requires

- None (foundational transport layer; first story in the unit)

### Enables

- 002-https-mitm-interception (HTTPS builds on the same Pingora `ProxyHttp` implementation)
- 005-config-and-startup (listen address configuration consumed here)
- All enforcement pipeline stories (request data flows into the enforcement pipeline)

## Edge Cases

| Scenario | Expected Behavior |
| -------- | ----------------- |
| Request with no body (GET, HEAD, DELETE) | Intercepted normally; body is empty/absent; no error |
| Request with very large body (>10 MB) | Buffered up to a configurable limit; requests exceeding the limit rejected with 413 |
| Malformed HTTP request (invalid method, missing host) | Rejected with 400 and Firma denial response (story 004) |
| Agent sends request to the proxy's own listen address | Rejected to prevent request loops; return 400 |
| Connection from agent drops mid-request | Proxy cleans up gracefully; no resource leak |
| Non-proxy HTTP request (direct request to proxy host without full URL) | Routed to health/readiness endpoints if matching; otherwise rejected with 400 |

## Out of Scope

- HTTPS CONNECT handling and TLS MITM (story 002)
- Enforcement decision logic (unit 002-enforcement-pipeline)
- Response-path evaluation of LLM tool calls (unit 004-llm-response-parser)
- Connection pooling to upstream targets (unit 005-connector-credentials)
- Audit event emission (unit 006-audit-observability)
