---
id: 001-execution-event-schema
unit: 006-audit-observability
intent: 006-sidecar-proxy-enforcement
status: draft
priority: must
created: 2026-04-05T12:00:00Z
assigned_bolt: null
implemented: false
---

# Story: 001-execution-event-schema

## User Story

**As the** audit system
**I want** a well-defined ExecutionEvent struct containing all FEP §15 minimum audit fields
**So that** every enforcement decision produces a complete, structured record

## Acceptance Criteria

- [ ] **Given** the ExecutionEvent struct definition, **When** inspected, **Then** it contains all FEP §15 minimum audit fields: `event_id` (UUID v7), `session_id`, `agent_id`, `token_id`, `action_class`, `resource`, `decision` (ALLOW/DENY/ABORT), `deny_reason` (nullable), `enforcement_latency_us`, `context_hash`, `bundle_version`, `registry_version`, `trace_id`, `timestamp_ns`, and `signature` (populated by the signing layer, story 002)
- [ ] **Given** a Stage 1 or Stage 2 ALLOW decision, **When** the enforcement pipeline completes, **Then** an ExecutionEvent is emitted with `decision = ALLOW` and `deny_reason = null`
- [ ] **Given** a Stage 1 or Stage 2 DENY decision, **When** the enforcement pipeline completes, **Then** an ExecutionEvent is emitted with `decision = DENY` and `deny_reason` set to the specific reason code (e.g., `TOKEN_EXPIRED`, `POLICY_DENIED`, `SCOPE_VIOLATION`)
- [ ] **Given** an ABORT condition (internal failure), **When** the enforcement pipeline encounters an unrecoverable error, **Then** an ExecutionEvent is emitted with `decision = ABORT` and `deny_reason` describing the failure
- [ ] **Given** any enforcement decision path in the Sidecar, **When** the decision is made, **Then** an ExecutionEvent is always emitted (no silent decision paths)
- [ ] **Given** an ExecutionEvent instance, **When** serialized, **Then** it produces valid JSON with all fields present (nullable fields serialized as `null`, not omitted)

## Technical Notes

- `event_id` should use UUID v7 (time-ordered) for natural chronological sorting — use the `uuid` crate with v7 feature
- `timestamp_ns` is nanosecond-precision Unix timestamp (u64 or i64) — use `std::time::SystemTime` or `chrono`
- `enforcement_latency_us` is the total time from request interception to decision, in microseconds
- `context_hash` is a hash of the Cedar evaluation context (for reproducibility audits) — SHA-256 of the serialized context
- `bundle_version` and `registry_version` are strings identifying the policy bundle and action class registry versions active at decision time
- `trace_id` enables correlation across distributed tracing systems (OpenTelemetry compatible)
- The `signature` field is initially empty/zero when the event is created; it is populated by the ECDSA signing layer (story 002) before emission
- Use `serde` derive macros for JSON serialization; all fields should have explicit `#[serde(rename)]` if the Rust field names differ from the JSON schema
- The `decision` field should be an enum: `Decision { Allow, Deny, Abort }`
- The `deny_reason` field should use the reason codes from FR-11: `TOKEN_INVALID`, `TOKEN_EXPIRED`, `TOKEN_REVOKED`, `POLICY_DENIED`, `BUDGET_EXCEEDED`, `SCOPE_VIOLATION`, `RISK_THRESHOLD`, `TOOL_NOT_IN_SCOPE`, `UNCLASSIFIED_INTENT`, `MALFORMED_REQUEST`, `AUTHORITY_UNAVAILABLE`, `POLICY_BUNDLE_STALE`, `CREDENTIAL_INJECTION_FAILED`, `CONNECTOR_TIMEOUT`
- Consider implementing `ExecutionEvent` with a builder pattern to ensure all required fields are set before construction

## Dependencies

### Requires

- firma-core (intent 002): `Decision` enum, reason code types (if shared)

### Enables

- 002-ecdsa-audit-signing (signs the ExecutionEvent fields)
- 003-audit-sinks (serializes and emits ExecutionEvent to sinks)
- All enforcement pipeline stories (every decision path must construct an ExecutionEvent)

## Edge Cases

| Scenario | Expected Behavior |
| -------- | ----------------- |
| Enforcement decision occurs before session_id is established | `session_id` set to a sentinel value or "unknown"; event still emitted |
| Token is missing or unparseable (no token_id available) | `token_id` set to `null` or "unknown"; event still emitted with available fields |
| Enforcement latency measurement overflows microsecond counter | Use u64 (sufficient for ~584,000 years); practically impossible to overflow |
| Context hash computation fails (serialization error) | `context_hash` set to a sentinel value; event still emitted; log warning |
| Bundle version is unknown (policy source not yet synced) | `bundle_version` set to "unknown"; this condition should trigger POLICY_BUNDLE_STALE |
| Very high event creation rate (>10k events/sec) | Event creation is lightweight (struct construction); bottleneck is in sinks (story 003), not schema |
| Event created but signing fails (story 002) | Event emitted with empty/zero signature; log error; signing failure does not suppress the event |

## Out of Scope

- ECDSA signing of events (story 002)
- Emission to sinks (story 003)
- Prometheus metrics (story 004)
- Event aggregation, deduplication, or compression
- Event retention policies
- Event schema versioning (future enhancement for backward-compatible schema evolution)
