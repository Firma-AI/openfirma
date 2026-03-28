---
unit: 002-paseto-v4
intent: 002-core-types-shared-library
phase: inception
status: ready
created: 2026-03-26T14:10:00Z
updated: 2026-03-26T14:10:00Z
---

# Unit Brief: PASETO v4 Implementation

## Purpose

Implement `TokenSigner` and `TokenVerifier` for PASETO v4 using the `rusty_paseto` crate with Ed25519 keys. This is the primary token format for Firma — used by the Authority to issue tokens and by the Sidecar to validate them on every request.

## Scope

### In Scope

- `PasetoV4Signer` implementing `TokenSigner` — signs `CapabilityClaims` into a PASETO v4.public token
- `PasetoV4Verifier` implementing `TokenVerifier` — verifies and parses PASETO v4.public tokens back into `CapabilityClaims`
- Ed25519 key pair handling (accept keys, generate for tests)
- Comprehensive test suite: round-trip, expired, tampered, wrong key, malformed

### Out of Scope

- JWT RS256 implementation (deferred — trait is ready for it)
- Key management / rotation (deployment concern, not library concern)
- Token storage or caching (Sidecar local state, intent 006)

---

## Assigned Requirements

| FR | Requirement | Priority |
| -- | ----------- | -------- |
| FR-4 | PASETO v4 Implementation | Must |

---

## Domain Concepts

### Key Entities

| Entity | Description | Attributes |
| ------ | ----------- | ---------- |
| PasetoV4Signer | Signs capability claims into PASETO v4 tokens | Ed25519 private key |
| PasetoV4Verifier | Verifies PASETO v4 tokens and extracts claims | Ed25519 public key |

### Key Operations

| Operation | Description | Inputs | Outputs |
| --------- | ----------- | ------ | ------- |
| sign | Serialize claims to JSON, sign with Ed25519 private key, return PASETO v4.public token | CapabilityClaims, private key | Result<String, TokenError> |
| verify | Parse PASETO v4 token, verify Ed25519 signature, deserialize claims, check expiry | raw token string, public key | Result<CapabilityClaims, TokenError> |

---

## Story Summary

| Metric | Count |
| ------ | ----- |
| Total Stories | 3 |
| Must Have | 3 |
| Should Have | 0 |
| Could Have | 0 |

### Stories

| Story ID | Title | Priority | Status |
| -------- | ----- | -------- | ------ |
| 001-paseto-signer | PASETO v4 signer | Must | Planned |
| 002-paseto-verifier | PASETO v4 verifier | Must | Planned |
| 003-token-round-trip-tests | Token round-trip and rejection tests | Must | Planned |

---

## Dependencies

### Depends On

| Unit | Reason |
| ---- | ------ |
| 001-types-and-traits | Needs CapabilityClaims, TokenSigner, TokenVerifier, TokenError |

### Depended By

| Unit | Reason |
| ---- | ------ |
| Intent 005 units | Authority uses PasetoV4Signer to issue tokens |
| Intent 006 units | Sidecar uses PasetoV4Verifier in Stage 1 |

### External Dependencies

| System | Purpose | Risk |
| ------ | ------- | ---- |
| rusty_paseto | PASETO v4 token creation and verification | Medium — must verify Ed25519 v4.public support before construction |

---

## Technical Context

### Suggested Technology

`rusty_paseto` crate for PASETO v4. Ed25519 keys via `ed25519-dalek` or whatever `rusty_paseto` uses internally.

### Integration Points

None — pure library. Consumers call `sign()` and `verify()`.

### Data Storage

None.

---

## Constraints

- Must meet NFR-1: verify < 500µs, sign < 1ms
- Must use `rusty_paseto` per tech stack
- Must implement the `TokenSigner` and `TokenVerifier` traits exactly as defined in Unit 001
- No `.unwrap()` or `.expect()` — all errors mapped to `TokenError`

---

## Success Criteria

### Functional

- [ ] `PasetoV4Signer::sign` produces a valid PASETO v4.public token
- [ ] `PasetoV4Verifier::verify` correctly parses and validates tokens
- [ ] Round-trip: sign → verify → claims match original
- [ ] Expired token rejected with `TokenError::Expired`
- [ ] Tampered token rejected with `TokenError::SignatureInvalid`
- [ ] Wrong public key rejected with `TokenError::SignatureInvalid`
- [ ] Malformed input rejected with `TokenError::ParseFailure`

### Non-Functional

- [ ] Verify < 500µs per operation
- [ ] Sign < 1ms per operation
- [ ] Zero `unsafe` code

### Quality

- [ ] All acceptance criteria met
- [ ] Property-based tests for token validation edge cases (if applicable)

---

## Bolt Suggestions

| Bolt | Type | Stories | Objective |
| ---- | ---- | ------- | --------- |
| 003-paseto-v4 | DDD | 001, 002, 003 | PASETO v4 signer + verifier + comprehensive tests |

---

## Notes

Verify `rusty_paseto` supports PASETO v4.public (Ed25519) before starting construction. If it doesn't, `pasetors` is the fallback crate.
