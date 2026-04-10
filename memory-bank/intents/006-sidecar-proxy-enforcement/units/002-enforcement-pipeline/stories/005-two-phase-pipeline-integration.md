---
id: 005-two-phase-pipeline-integration
unit: 002-enforcement-pipeline
intent: 006-sidecar-proxy-enforcement
status: complete
priority: must
created: 2026-04-05T12:00:00.000Z
assigned_bolt: null
implemented: true
---

# Story: 005-two-phase-pipeline-integration

## User Story

**As the** enforcement pipeline
**I want** Stage 1 and Stage 2 wired into a single enforce() call that short-circuits on failure and produces a unified Decision
**So that** callers (proxy-core, llm-response-parser) interact with one clean interface

## Acceptance Criteria

- [ ] **Given** a raw request and a capability token, **When** enforce() is called, **Then** it accepts both inputs and orchestrates the full pipeline
- [ ] **Given** the enforce() pipeline, **When** Stage 1 (token validation) fails, **Then** it short-circuits immediately with a structured DENY and Stage 2 is never invoked
- [ ] **Given** the enforce() pipeline, **When** Stage 1 passes, **Then** Stage 2 (Cedar evaluation) runs with the verified token claims and normalized envelope
- [ ] **Given** any pipeline outcome, **When** enforce() returns, **Then** the result is a unified Decision type that is either ALLOW or DENY with a structured reason
- [ ] **Given** the enforce() interface, **When** proxy-core calls it on the request path, **Then** it works correctly for request-path enforcement
- [ ] **Given** the enforce() interface, **When** llm-response-parser calls it for a detected tool call, **Then** it works correctly for response-path enforcement (same pipeline, different caller)
- [ ] **Given** end-to-end enforcement (intent normalization + Stage 1 + Stage 2), **When** measured under load, **Then** the total pipeline overhead is less than 3ms p95
- [ ] **Given** a DENY decision from any stage, **When** the Decision is inspected, **Then** it contains: the reason code (e.g., TOKEN_EXPIRED, POLICY_DENIED, SCOPE_VIOLATION, UNCLASSIFIED_INTENT), a human-readable detail string, and the stage that produced the denial
- [ ] **Given** an ALLOW decision, **When** the Decision is inspected, **Then** it contains the verified CapabilityClaims and the normalized ExecutionEnvelope for downstream use (credential injection, audit)

## Technical Notes

- The enforce() function signature should accept:
  - A raw request representation (method, host, path, headers, body reference)
  - A capability token (raw string)
  - References to shared state: mapping table, Authority public key, revocation cache, policy bundle, Sidecar state
- Internal pipeline stages:
  1. Intent normalization (story 001): raw request -> ExecutionEnvelope (or DENY: UNCLASSIFIED_INTENT)
  2. Stage 1 (story 003): token validation (or DENY: TOKEN_INVALID / TOKEN_EXPIRED / TOKEN_REVOKED)
  3. Stage 2 (story 004): Cedar context build + policy evaluation + scope check (or DENY: POLICY_DENIED / SCOPE_VIOLATION / BUDGET_EXCEEDED)
- Short-circuit semantics: each stage returns a Result-like type; on Err, the pipeline returns immediately
- The Decision type should carry enough information for:
  - The caller to construct the appropriate response (HTTP 403 or provider-native denial)
  - The audit emitter to log all relevant fields
  - The connector/credential injector to proceed on ALLOW
- The enforce() function should be stateless with respect to the request -- all mutable state (counters, caches) is accessed via shared references (Arc<RwLock> or similar)
- Consider making enforce() async-compatible even if the current implementation is synchronous, to allow future non-blocking extensions
- The pipeline must be reentrant: multiple concurrent enforce() calls must not interfere with each other

## Dependencies

### Requires

- 001-intent-normalizer (intent normalization is the first pipeline step)
- 002-unclassified-intent-denial (UNCLASSIFIED_INTENT is a pre-Stage-1 denial path)
- 003-stage1-token-validation (Stage 1 is the second pipeline step)
- 004-stage2-cedar-evaluation (Stage 2 is the third pipeline step)
- firma-core (intent 002): `Decision` type, `CapabilityClaims`, `ExecutionEnvelope`

### Enables

- 001-proxy-core (unit 001): calls enforce() from Pingora request lifecycle hooks
- 004-llm-response-parser (unit 004): calls enforce() for each detected tool call
- 006-audit-observability (unit 006): consumes Decision for audit event emission

## Edge Cases

| Scenario | Expected Behavior |
| -------- | ----------------- |
| Intent normalization fails (UNCLASSIFIED_INTENT) | DENY returned; Stage 1 and Stage 2 never run |
| Stage 1 fails (TOKEN_INVALID) | DENY returned; Stage 2 never runs |
| Stage 1 passes but Stage 2 fails (POLICY_DENIED) | DENY returned from Stage 2 |
| Both Stage 1 and Stage 2 would fail | Only Stage 1 failure is reported (short-circuit) |
| enforce() called with empty/null token | DENY: TOKEN_INVALID at Stage 1 |
| enforce() called with valid token but request to unknown host | DENY: UNCLASSIFIED_INTENT at normalization (if host is protected) |
| Policy bundle is stale (TTL expired) | DENY: POLICY_BUNDLE_STALE at Stage 2 (or pre-Stage-2 check) |
| Concurrent enforce() calls for different requests | Each runs independently; no cross-request interference |
| Concurrent enforce() calls for the same token | Both proceed independently; token validation is idempotent |
| enforce() called after Sidecar shutdown signal | Depends on drain configuration; in-flight calls complete, new calls rejected |
| Panic in any pipeline stage | Must not propagate to caller; caught and converted to DENY with internal error reason |

## Out of Scope

- Retry logic for transient failures (enforcement is single-shot; the agent retries at the application level)
- Caching of enforcement decisions (each request is evaluated independently)
- Async event emission from within enforce() (audit emission is the caller's responsibility after receiving the Decision)
- HTTP response formatting (owned by unit 001-proxy-core and unit 004-llm-response-parser)
- Credential injection and connector dispatch (owned by unit 005-connector-credentials; triggered by caller on ALLOW)
