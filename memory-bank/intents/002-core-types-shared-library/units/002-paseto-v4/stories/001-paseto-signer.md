---
id: 001-paseto-signer
unit: 002-paseto-v4
intent: 002-core-types-shared-library
status: complete
priority: must
created: 2026-03-26T14:10:00.000Z
assigned_bolt: null
implemented: true
---

# Story: 001-paseto-signer

## User Story

**As a** Mini Authority developer
**I want** a PASETO v4 token signer that implements the `TokenSigner` trait
**So that** I can issue signed capability tokens to Sidecars during pre-flight

## Acceptance Criteria

- [ ] **Given** a `PasetoV4Signer` constructed with an Ed25519 private key, **When** I call `sign(&claims)`, **Then** it returns a PASETO v4.public token string
- [ ] **Given** valid `CapabilityClaims`, **When** I sign them, **Then** the token payload contains all claims fields as JSON
- [ ] **Given** any signing error, **When** it occurs, **Then** it is mapped to `TokenError` (no panics, no unwraps)
- [ ] **Given** a `PasetoV4Signer`, **When** used as `&dyn TokenSigner`, **Then** it compiles (trait object compatible)

## Technical Notes

- PASETO v4.public uses Ed25519 signatures
- Claims are serialized to JSON and embedded in the PASETO payload
- The `rusty_paseto` API may require specific claim registration — map our `CapabilityClaims` fields appropriately
- Signing latency target: < 1ms

## Dependencies

### Requires

- Unit 001 stories (CapabilityClaims, TokenSigner trait, TokenError)

### Enables

- 002-paseto-verifier (verifier validates what signer produces)
- 003-token-round-trip-tests (round-trip test needs both)

## Edge Cases

| Scenario | Expected Behavior |
| -------- | ----------------- |
| Claims with empty actions/resources | Signs successfully — validation is verifier's job |
| Very large claims payload | Signs successfully — PASETO has no payload size limit in practice |
| Invalid private key bytes | Returns TokenError, not a panic |

## Out of Scope

- Key generation (test helper only — production key management is deployment concern)
- Key rotation
