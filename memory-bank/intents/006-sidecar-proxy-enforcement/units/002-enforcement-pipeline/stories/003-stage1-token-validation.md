---
id: 003-stage1-token-validation
unit: 002-enforcement-pipeline
intent: 006-sidecar-proxy-enforcement
status: complete
priority: must
created: 2026-04-05T12:00:00.000Z
assigned_bolt: null
implemented: true
---

# Story: 003-stage1-token-validation

## User Story

**As the** enforcement pipeline
**I want** Stage 1 to validate capability tokens (parse, verify signature, check expiry, check revocation) without contacting the Authority
**So that** invalid tokens are rejected in under 1ms with no network dependency

## Acceptance Criteria

- [ ] **Given** a valid PASETO v4 token, **When** Stage 1 processes it, **Then** the token is parsed and its cryptographic signature is verified using the firma-core `TokenVerifier` trait
- [ ] **Given** a token whose `expires_at` is in the past, **When** Stage 1 checks expiry, **Then** it returns DENY with reason code TOKEN_EXPIRED
- [ ] **Given** a token whose `token_id` is present in the revocation cache, **When** Stage 1 checks revocation, **Then** it returns DENY with reason code TOKEN_REVOKED
- [ ] **Given** a token whose `token_id` is not in the bloom filter, **When** the revocation check runs, **Then** the token is confirmed non-revoked in O(1) time (bloom filter negative = definitive non-revoked)
- [ ] **Given** a token whose `token_id` triggers a bloom filter positive, **When** the LRU cache is consulted, **Then** the cache confirms or denies revocation (bloom filter positive alone is not sufficient to deny)
- [ ] **Given** a token with a tampered payload or forged signature, **When** Stage 1 verifies it, **Then** it returns DENY with reason code TOKEN_INVALID
- [ ] **Given** any Stage 1 validation, **When** measured under load, **Then** the p95 latency is less than 1ms
- [ ] **Given** a token that passes all Stage 1 checks, **When** validation completes, **Then** the ExecutionEnvelope proceeds to Stage 2
- [ ] **Given** a token that fails any Stage 1 check, **When** the failure is detected, **Then** a structured DENY is returned immediately (Stage 2 is never invoked)
- [ ] **Given** any Stage 1 operation, **When** it executes, **Then** the Authority is never contacted (fully local validation)

## Technical Notes

- Stage 1 uses the firma-core `TokenVerifier` trait, which handles PASETO v4 parsing and Ed25519 signature verification
- The Authority's public key is loaded at startup and cached in memory; it is not fetched per-request
- Revocation check uses a two-layer cache provided by unit 003-policy-revocation:
  - Layer 1: Bloom filter for O(1) negative checks (if not in bloom filter, definitively not revoked)
  - Layer 2: LRU cache for confirmed positives (if bloom filter says "maybe revoked", check LRU for confirmed revocations)
- The bloom filter has a configurable false positive rate (e.g., 0.01); false positives cause an LRU lookup, not a denial
- Token fields extracted after verification: token_id, agent_id, session_id, actions, resources, expires_at
- Clock skew tolerance for expiry checks should be configurable (default: 0 seconds, strict)
- Stage 1 does not evaluate Cedar policies, check scope, or build context -- those are Stage 2 responsibilities

## Dependencies

### Requires

- firma-core (intent 002): `TokenVerifier` trait, `CapabilityClaims` type, `TokenError` variants
- 003-policy-revocation (unit 003): revocation cache (bloom filter + LRU) must be readable by Stage 1

### Enables

- 004-stage2-cedar-evaluation (receives verified token claims for context building and scope check)
- 005-two-phase-pipeline-integration (Stage 1 is the first phase of the two-phase pipeline)

## Edge Cases

| Scenario | Expected Behavior |
| -------- | ----------------- |
| Token is missing entirely from the request | DENY: TOKEN_INVALID with detail "no capability token provided" |
| Token is present but not valid PASETO v4 format | DENY: TOKEN_INVALID with detail "malformed token" |
| Token signature is valid but payload is not valid JSON | DENY: TOKEN_INVALID with detail "invalid token payload" |
| Token is expired by less than 1 second | DENY: TOKEN_EXPIRED (no grace period unless clock skew tolerance is configured) |
| Token expires exactly at the current timestamp | DENY: TOKEN_EXPIRED (expiry boundary is exclusive) |
| Bloom filter returns false positive for a non-revoked token | LRU cache consulted; LRU miss means not revoked; token proceeds to Stage 2 |
| Revocation cache is empty (no revocations loaded yet) | All tokens pass revocation check (bloom filter is empty, no positives) |
| Authority public key not loaded at startup | Sidecar fails to start (fail-fast); no requests are processed |
| Token has valid signature but unknown/extra claims fields | Parsed successfully; unknown fields ignored; required fields validated |
| Concurrent Stage 1 validations for the same token | Each validation runs independently; no shared mutable state in the hot path |

## Out of Scope

- Refreshing or rotating the Authority public key at runtime (key rotation is a post-V1 concern)
- Contacting the Authority for real-time revocation checks (Stage 1 is fully local)
- Scope validation (whether the action is within the token's allowed action set -- that is Stage 2)
- Cedar policy evaluation (Stage 2 responsibility)
- Populating or updating the revocation cache (owned by unit 003-policy-revocation)
