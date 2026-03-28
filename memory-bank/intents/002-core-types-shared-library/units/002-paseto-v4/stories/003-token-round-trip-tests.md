---
id: 003-token-round-trip-tests
unit: 002-paseto-v4
intent: 002-core-types-shared-library
status: draft
priority: must
created: 2026-03-26T14:10:00Z
assigned_bolt: null
implemented: false
---

# Story: 003-token-round-trip-tests

## User Story

**As a** Firma developer
**I want** comprehensive tests proving PASETO v4 sign/verify works correctly and rejects invalid tokens
**So that** I can trust the cryptographic foundation before building Stage 1 and the Authority on top of it

## Acceptance Criteria

- [ ] **Given** a key pair and valid claims, **When** I sign then verify, **Then** the returned claims match the original exactly
- [ ] **Given** a signed token, **When** I modify one byte and verify, **Then** it returns SignatureInvalid
- [ ] **Given** a signed token, **When** I verify with a different public key, **Then** it returns SignatureInvalid
- [ ] **Given** claims with expires_at 1 second in the past, **When** I sign and immediately verify, **Then** it returns Expired
- [ ] **Given** claims with expires_at 10 minutes in the future, **When** I sign and verify, **Then** it succeeds
- [ ] **Given** a random non-PASETO string, **When** I verify it, **Then** it returns ParseFailure
- [ ] **Given** an empty string, **When** I verify it, **Then** it returns ParseFailure
- [ ] **Given** the verify operation, **When** benchmarked, **Then** it completes in < 500µs

## Technical Notes

- Use a test helper to generate Ed25519 key pairs
- Consider property-based tests (proptest) for claims field permutations
- Benchmark test can use `std::time::Instant` for a rough check; formal benchmarks via `criterion` are optional
- Test expired tokens by constructing claims with a past `expires_at`, not by sleeping

## Dependencies

### Requires

- 001-paseto-signer (produces tokens)
- 002-paseto-verifier (validates tokens)

### Enables

- None (terminal story — validates the unit)

## Edge Cases

| Scenario | Expected Behavior |
| -------- | ----------------- |
| Claims with unicode in agent_id | Round-trips correctly |
| Claims with maximum field lengths | Round-trips correctly |
| Concurrent sign operations | Each produces a valid, independent token |
| Token signed with key A, verified with key B (both valid keys) | SignatureInvalid |

## Out of Scope

- Integration tests with Sidecar or Authority (intents 005/006)
- Performance benchmarks with criterion (nice-to-have, not required)
