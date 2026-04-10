---
id: 002-grpc-policy-source
unit: 003-policy-revocation
intent: 006-sidecar-proxy-enforcement
status: draft
priority: must
created: 2026-04-05T12:00:00Z
assigned_bolt: null
implemented: false
---

# Story: 002-grpc-policy-source

## User Story

**As a** production operator
**I want** the Sidecar to receive policy updates from the Authority via gRPC streaming
**So that** policy changes propagate automatically without filesystem access

## Acceptance Criteria

- [ ] **Given** `--authority-url` is configured, **When** the Sidecar starts, **Then** it connects to `AuthorityService.WatchPolicyBundle` server-streaming RPC and receives the initial full policy bundle
- [ ] **Given** an active `WatchPolicyBundle` stream, **When** the Authority pushes an incremental policy update, **Then** the Sidecar applies the update to its in-memory policy set
- [ ] **Given** an active `WatchPolicyBundle` stream, **When** the stream disconnects, **Then** the Sidecar starts a TTL countdown (configurable, default 30s) using the last successful update timestamp
- [ ] **Given** the stream is disconnected and the TTL has expired, **When** a new enforcement request arrives, **Then** the Sidecar enters fail-closed mode and denies all requests with reason code `POLICY_BUNDLE_STALE`
- [ ] **Given** the stream was disconnected and TTL has not expired, **When** the Sidecar reconnects to the Authority, **Then** the Authority pushes a full bundle and the Sidecar resumes normal operation, resetting the TTL
- [ ] **Given** the Authority pushes a new bundle that fails to parse or compile, **When** the Sidecar receives it, **Then** the malformed bundle is rejected with a logged error and the last valid bundle is retained
- [ ] **Given** a policy bundle is received and activated, **When** the bundle version is recorded, **Then** the version is tracked and included in subsequent audit events
- [ ] **Given** `--authority-url` is not configured, **When** the Sidecar starts, **Then** the gRPC policy source is not activated (file mode is used instead)

## Technical Notes

- Implement the `PolicySource` trait for a `GrpcPolicySource` struct
- Use `tonic` for the gRPC client connecting to `AuthorityService.WatchPolicyBundle`
- The initial message on the stream should be a full bundle; subsequent messages may be incremental (add/remove individual policies)
- TTL countdown begins on stream disconnect, not on the last message received; resets on successful reconnect
- Reconnection should use exponential backoff with jitter (e.g., 100ms initial, 2x multiplier, 30s max, +/- 20% jitter)
- Bundle swap uses the same atomic mechanism as file mode (`Arc` + `arc_swap` or equivalent)
- Bundle version comes from the Authority's `PolicyBundleUpdate` message (defined in firma-proto)
- The `POLICY_BUNDLE_STALE` denial must propagate through the standard denial response format (FR-11)
- During TTL countdown (stream disconnected but TTL not expired), the Sidecar continues serving with the cached bundle
- Consider emitting a metric/log when entering degraded mode (stream disconnected, TTL counting down)

## Dependencies

### Requires

- firma-proto (intent 003): `AuthorityService.WatchPolicyBundle` RPC definition, `PolicyBundleUpdate` message
- `PolicySource` trait (defined in story 001 or firma-core)
- `tonic` crate for gRPC client
- `cedar-policy` crate for policy compilation

### Enables

- Unit 002-enforcement-pipeline Stage 2 (consumes the compiled policy bundle)
- Unit 006-audit-observability (bundle version included in audit events)

## Edge Cases

| Scenario | Expected Behavior |
| -------- | ----------------- |
| Authority is unreachable at Sidecar startup | Sidecar retries connection with exponential backoff; readiness check (`/readyz`) returns 503 until initial bundle is received |
| Authority sends an empty initial bundle (zero policies) | Treated as valid (no policies = deny-all under Cedar default-deny semantics); log warning |
| Stream reconnects but Authority pushes a bundle with an older version than the current cached one | Accept the Authority's bundle (Authority is the source of truth); log the version regression |
| Network partition causes intermittent stream resets | Each disconnect restarts the TTL countdown; rapid reconnect before TTL expiry keeps the Sidecar operational |
| Authority pushes a very large bundle (>10 MB) | Accept up to a configurable max bundle size (default 50 MB); reject bundles exceeding the limit |
| Concurrent policy evaluation during bundle swap | Atomic swap ensures in-flight evaluations complete against the old bundle; new evaluations use the new bundle |
| Authority stream sends duplicate bundle version | Idempotent: re-apply the bundle (content-addressed comparison optional); no error |
| TLS certificate validation fails when connecting to Authority | Fail to connect; log error; retry with backoff; readiness check returns 503 |

## Out of Scope

- File-based policy sourcing (story 001)
- Authority server implementation (intent 005)
- Policy evaluation logic (unit 002-enforcement-pipeline)
- Mutual TLS (mTLS) authentication to the Authority (post-V1)
- Policy bundle signing and signature verification (post-V1)
