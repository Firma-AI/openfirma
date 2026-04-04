---
id: 004-grpc-revocation-source
unit: 003-policy-revocation
intent: 006-sidecar-proxy-enforcement
status: draft
priority: must
created: 2026-04-05T12:00:00Z
assigned_bolt: null
implemented: false
---

# Story: 004-grpc-revocation-source

## User Story

**As a** production operator
**I want** the Sidecar to receive revocation events from the Authority via gRPC streaming
**So that** token revocations propagate in near real-time

## Acceptance Criteria

- [ ] **Given** `--authority-url` is configured, **When** the Sidecar starts, **Then** it connects to `AuthorityService.WatchRevocations` server-streaming RPC and receives existing revocation entries
- [ ] **Given** an active `WatchRevocations` stream, **When** the Authority pushes a revocation event, **Then** the bloom filter and LRU cache are updated with the new revocation entry
- [ ] **Given** a revocation event is received from the Authority, **When** measured end-to-end from source update to Stage 1 rejection of the revoked token, **Then** propagation latency is < 1s at p99
- [ ] **Given** an active `WatchRevocations` stream, **When** the stream disconnects, **Then** the Sidecar continues operating with the existing revocation cache (no fail-closed for revocation stream disconnect)
- [ ] **Given** the `RevocationSource` trait is defined, **When** a community developer implements it, **Then** they can provide custom revocation source backends without modifying the Sidecar

## Technical Notes

- Implement the `RevocationSource` trait for a `GrpcRevocationSource` struct
- Use `tonic` for the gRPC client connecting to `AuthorityService.WatchRevocations`
- Unlike the policy source (story 002), revocation stream disconnect does NOT trigger fail-closed behavior; the existing cache remains valid because revocations are append-only (a previously revoked token stays revoked)
- On reconnect, the Authority should send all revocations that occurred since the last known event (or a full snapshot); the Sidecar should track the last received event sequence number or timestamp to support this
- Each revocation event contains at minimum: `token_id`, `revoked_at`, and optional `reason`
- Events are pushed into the shared revocation cache (story 005) via its update interface
- Bloom filter updates are incremental (add only); no rebuild required for additions
- LRU cache entries are added on each revocation event
- Reconnection should use exponential backoff with jitter (same strategy as story 002: 100ms initial, 2x multiplier, 30s max, +/- 20% jitter)
- Consider emitting a metric when the revocation stream is disconnected (degraded mode)

## Dependencies

### Requires

- firma-proto (intent 003): `AuthorityService.WatchRevocations` RPC definition, `RevocationEvent` message
- 005-revocation-cache (provides the bloom filter + LRU cache to populate)
- `RevocationSource` trait definition (defined in story 003 or in firma-core)
- `tonic` crate for gRPC client

### Enables

- Unit 002-enforcement-pipeline Stage 1 (reads the revocation cache for token revocation checks)

## Edge Cases

| Scenario | Expected Behavior |
| -------- | ----------------- |
| Authority is unreachable at Sidecar startup | Sidecar starts with empty revocation cache; retries connection with exponential backoff; readiness not blocked (revocation is additive) |
| Authority sends a burst of revocation events | All events processed and applied to cache; no event dropped; back-pressure handled via gRPC flow control |
| Duplicate revocation event (same `token_id`) received | Idempotent: bloom filter is unaffected (already set); LRU entry updated with latest timestamp |
| Revocation stream reconnects after extended outage | Authority sends missed revocations since last known sequence; bloom filter and LRU updated |
| Very high revocation rate (>1000 events/second) | Events applied as fast as received; log warning if processing falls behind; no artificial rate limiting |
| Network partition causes intermittent stream resets | Each disconnect triggers reconnection with backoff; existing cache remains valid throughout |
| Authority sends a revocation for a token not yet seen by this Sidecar | Added to cache normally; when the token is eventually presented, it will be caught at Stage 1 |
| TLS certificate validation fails when connecting to Authority | Fail to connect; log error; retry with backoff; Sidecar continues with existing cache |

## Out of Scope

- File-based revocation sourcing (story 003)
- Revocation cache implementation details (story 005)
- Authority server implementation (intent 005)
- Token validation logic (unit 002-enforcement-pipeline)
- Revocation event persistence to disk (cache is in-memory only)
- Mutual TLS (mTLS) authentication to the Authority (post-V1)
- Revocation event signing and signature verification (post-V1)
