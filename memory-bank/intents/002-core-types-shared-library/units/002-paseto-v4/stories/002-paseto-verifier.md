---
id: 002-paseto-verifier
unit: 002-paseto-v4
intent: 002-core-types-shared-library
status: complete
priority: must
created: 2026-03-26T14:10:00.000Z
assigned_bolt: null
implemented: true
---

# Story: 002-paseto-verifier

## User Story

**As a** Sidecar developer
**I want** a PASETO v4 token verifier that implements the `TokenVerifier` trait
**So that** Stage 1 can validate capability tokens on every outbound call

## Acceptance Criteria

- [ ] **Given** a `PasetoV4Verifier` constructed with an Ed25519 public key, **When** I call `verify(token_string)`, **Then** it returns parsed `CapabilityClaims` on success
- [ ] **Given** a valid token, **When** verified with the correct public key, **Then** all claims fields match the original
- [ ] **Given** an expired token, **When** I verify it, **Then** it returns `TokenError::Expired`
- [ ] **Given** a tampered token, **When** I verify it, **Then** it returns `TokenError::SignatureInvalid`
- [ ] **Given** a token verified with the wrong public key, **When** I verify it, **Then** it returns `TokenError::SignatureInvalid`
- [ ] **Given** a malformed string (not a PASETO token), **When** I verify it, **Then** it returns `TokenError::ParseFailure`
- [ ] **Given** a `PasetoV4Verifier`, **When** used as `&dyn TokenVerifier`, **Then** it compiles

## Technical Notes

- Verification steps: parse PASETO v4.public → verify Ed25519 signature → deserialize JSON payload → check expiry → return CapabilityClaims
- Expiry check: compare `expires_at` claim against current time. Use a clock abstraction or accept a `now` parameter for testability.
- Verification latency target: < 500µs (critical for Stage 1 p95 budget)
- Map all `rusty_paseto` errors to `TokenError` variants

## Dependencies

### Requires

- 001-paseto-signer (need signed tokens to verify)
- Unit 001 stories (CapabilityClaims, TokenVerifier trait, TokenError)

### Enables

- 003-token-round-trip-tests (verifier completes the round-trip)

## Edge Cases

| Scenario | Expected Behavior |
| -------- | ----------------- |
| Token expires exactly at current time | Treat as expired (strictly less than, not less-or-equal) |
| Token with no expiry claim | Return TokenError::ParseFailure (expiry is required) |
| Token with future issued_at | Accept — clock skew is not validated in V1 |
| Empty token string | Return TokenError::ParseFailure |

## Out of Scope

- Revocation check (that uses RevocationStore, handled in Sidecar Stage 1, intent 006)
- Scope validation (that's Stage 2 / Cedar eval)
