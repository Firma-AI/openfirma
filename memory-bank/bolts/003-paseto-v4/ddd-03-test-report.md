---
unit: 002-paseto-v4
bolt: 003-paseto-v4
stage: test
status: complete
updated: 2026-03-28T11:30:00Z
---

# Test Report — PASETO v4

## Test Summary

| Category | Passed | Failed | Skipped | Notes |
|----------|--------|--------|---------|-------|
| Unit | 16 | 0 | 0 | Co-located in paseto.rs |
| Integration | 0 | 0 | 0 | N/A — pure library, no cross-crate integration needed |
| Security | 4 | 0 | 0 | Tampered, wrong key, malformed, empty (subset of unit tests) |
| Performance | 2 | 0 | 0 | Verify < 500us, sign < 1ms (subset of unit tests) |
| **Total** | **16** | **0** | **0** | |

## Acceptance Criteria Validation

### Story 001: PASETO v4 Signer

| Criteria | Test | Status |
|----------|------|--------|
| `PasetoV4Signer` with Ed25519 key, `sign(&claims)` returns v4.public token | `test_sign_produces_v4_public_token` | ✅ |
| Token payload contains all claims fields as JSON | `test_round_trip_claims_match` (verify extracts all 8 fields) | ✅ |
| Signing errors mapped to `TokenError` (no panics, no unwraps) | `test_invalid_secret_key_bytes` | ✅ |
| `PasetoV4Signer` usable as `&dyn TokenSigner` | `test_signer_as_dyn_token_signer` | ✅ |

### Story 002: PASETO v4 Verifier

| Criteria | Test | Status |
|----------|------|--------|
| `PasetoV4Verifier` with Ed25519 public key, `verify(token)` returns `CapabilityClaims` | `test_round_trip_claims_match` | ✅ |
| All claims fields match original on valid token | `test_round_trip_claims_match` (8 field assertions) | ✅ |
| Expired token returns `TokenError::Expired` | `test_expired_token_rejected` | ✅ |
| Tampered token returns `TokenError::SignatureInvalid` | `test_tampered_token_rejected` | ✅ |
| Wrong public key returns `TokenError::SignatureInvalid` | `test_wrong_public_key_rejected` | ✅ |
| Malformed string returns `TokenError::ParseFailure` | `test_verify_malformed_string` | ✅ |
| `PasetoV4Verifier` usable as `&dyn TokenVerifier` | `test_verifier_as_dyn_token_verifier` | ✅ |

### Story 003: Round-trip and Rejection Tests

| Criteria | Test | Status |
|----------|------|--------|
| Sign → verify → claims match exactly | `test_round_trip_claims_match` | ✅ |
| Modified byte → SignatureInvalid | `test_tampered_token_rejected` | ✅ |
| Different public key → SignatureInvalid | `test_wrong_public_key_rejected` | ✅ |
| expires_at 1s in past → Expired | `test_expired_token_rejected` | ✅ |
| expires_at 10m in future → succeeds | `test_future_token_accepted` | ✅ |
| Random non-PASETO string → ParseFailure | `test_verify_malformed_string` | ✅ |
| Empty string → ParseFailure | `test_verify_empty_string` | ✅ |
| Verify < 500us | `test_verify_performance` | ✅ |
| Sign < 1ms | `test_sign_performance` | ✅ |

### Edge Cases

| Criteria | Test | Status |
|----------|------|--------|
| Empty actions/resources round-trip | `test_round_trip_empty_actions_resources` | ✅ |
| Unicode agent_id round-trip | `test_round_trip_unicode_agent_id` | ✅ |
| Invalid secret key bytes (wrong size) | `test_invalid_secret_key_bytes` | ✅ |
| Invalid public key bytes (wrong size) | `test_invalid_public_key_bytes` | ✅ |

## Bolt Success Criteria

| Criteria | Status |
|----------|--------|
| `PasetoV4Signer::sign` produces valid PASETO v4.public tokens | ✅ |
| `PasetoV4Verifier::verify` round-trips correctly | ✅ |
| Expired tokens rejected | ✅ |
| Tampered tokens rejected | ✅ |
| Wrong key rejected | ✅ |
| Malformed input rejected | ✅ |
| Verify < 500us | ✅ |
| Sign < 1ms | ✅ |
| `cargo build --workspace` succeeds | ✅ |
| `cargo clippy --workspace -- -D warnings` passes | ✅ |
| `cargo fmt --check` passes | ✅ |
| Zero `unsafe` code | ✅ (workspace deny + pasetors forbid) |
| No `.unwrap()` or `.expect()` in library code | ✅ |

## Performance Results

| Operation | Target | Measured (per-op avg, 100 iterations) | Status |
|-----------|--------|--------------------------------------|--------|
| Verify | < 500us | ~60-100us typical | ✅ |
| Sign | < 1ms | ~50-80us typical | ✅ |

Both operations well within NFR-1 budget. Ed25519 operations via `ed25519-compact` are fast on modern hardware.

## Issues Found

None.

## Ready for Operations

- [x] All acceptance criteria met (all 3 stories, all criteria verified)
- [x] No critical/high severity issues open
- [x] Performance targets met (NFR-1)
- [x] Security tests passing (tampered, wrong key, malformed, empty)
- [x] All Clippy pedantic lints pass
- [x] Zero unsafe code (both firma-core and pasetors)
