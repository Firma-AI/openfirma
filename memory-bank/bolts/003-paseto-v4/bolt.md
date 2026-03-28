---
id: 003-paseto-v4
unit: 002-paseto-v4
intent: 002-core-types-shared-library
type: ddd-construction-bolt
status: in-progress
started: 2026-03-28T10:45:00Z
current_stage: domain-model
stories:
  - 001-paseto-signer
  - 002-paseto-verifier
  - 003-token-round-trip-tests
created: 2026-03-26T14:10:00Z
stages_completed: []
requires_bolts:
  - 002-types-and-traits
enables_bolts: []
requires_units: []
blocks: false
complexity:
  avg_complexity: 2
  avg_uncertainty: 2
  max_dependencies: 2
  testing_scope: 2
---

# Bolt: 003-paseto-v4

## Objective

Implement PASETO v4 token signing and verification. After this bolt, the Authority can issue tokens and the Sidecar can validate them.

## Stories Included

- [ ] **001-paseto-signer**: PasetoV4Signer implementing TokenSigner (Must)
- [ ] **002-paseto-verifier**: PasetoV4Verifier implementing TokenVerifier (Must)
- [ ] **003-token-round-trip-tests**: Comprehensive sign/verify/reject test suite (Must)

## Bolt Type

**Type**: DDD Construction Bolt
**Definition**: `.specsmd/aidlc/templates/construction/bolt-types/ddd-construction-bolt.md`

## Stages

- [ ] **1. Domain Model**: Define PasetoV4Signer and PasetoV4Verifier structs, key handling approach
- [ ] **2. Technical Design**: Module layout, rusty_paseto API mapping, error conversion strategy
- [ ] **3. Implementation**: Write signer, verifier, key helpers, all error mapping
- [ ] **4. Test**: Round-trip, expired, tampered, wrong key, malformed, performance check
- [ ] **5. Review**: Verify NFR-1 (< 500µs verify, < 1ms sign), Clippy clean, no unsafe

## Expected Outputs

- `firma-core/src/paseto.rs` — PasetoV4Signer, PasetoV4Verifier implementations
- Updated `firma-core/Cargo.toml` with `rusty_paseto` dependency
- Test module with all acceptance criteria from stories 001-003

## Dependencies

### Bolt Dependencies (within intent)

- **002-types-and-traits** (Required): Needs CapabilityClaims, TokenSigner, TokenVerifier, TokenError

### Unit Dependencies (cross-unit)

- None

### Enables (other bolts waiting on this)

- Intent 005 bolts (Authority token generation)
- Intent 006 bolts (Sidecar Stage 1 validation)

## Success Criteria

- [ ] `PasetoV4Signer::sign` produces valid PASETO v4.public tokens
- [ ] `PasetoV4Verifier::verify` round-trips correctly
- [ ] Expired tokens rejected
- [ ] Tampered tokens rejected
- [ ] Wrong key rejected
- [ ] Malformed input rejected
- [ ] Verify < 500µs
- [ ] Sign < 1ms
- [ ] `cargo build --workspace` succeeds
- [ ] `cargo clippy --workspace -- -D warnings` passes

## Notes

Uncertainty is medium because `rusty_paseto` API specifics need to be verified during construction. If the crate doesn't support v4.public with Ed25519, fall back to `pasetors` crate.
