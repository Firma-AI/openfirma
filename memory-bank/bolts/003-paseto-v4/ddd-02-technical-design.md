---
unit: 002-paseto-v4
bolt: 003-paseto-v4
stage: design
status: complete
updated: 2026-03-28T11:00:00Z
---

# Technical Design — PASETO v4

## Architecture Pattern

**Single module extension** — adds one new module (`paseto.rs`) to the existing `firma-core` crate. No new crates, no new layers. `PasetoV4Signer` and `PasetoV4Verifier` implement the traits already defined in `traits.rs`.

---

## Module Structure

```text
crates/firma-core/
└── src/
    ├── lib.rs          # Add: mod paseto; pub use paseto::*;
    ├── token.rs        # (unchanged)
    ├── envelope.rs     # (unchanged)
    ├── decision.rs     # (unchanged)
    ├── error.rs        # (unchanged)
    ├── traits.rs       # (unchanged)
    └── paseto.rs       # NEW: PasetoV4Signer, PasetoV4Verifier
```

Single file is appropriate — two structs, two trait impls, helper functions for claims serialization/deserialization. No sub-modules needed.

---

## Crate Selection: `pasetors` (not `rusty_paseto`)

**Decision**: Use `pasetors` 0.7.8 instead of `rusty_paseto` 0.9.0.

This deviates from the tech stack (`tech-stack.md` specifies `rusty_paseto`). A formal ADR will be created in Stage 3. Summary rationale:

| Factor | `rusty_paseto` 0.9.0 | `pasetors` 0.7.8 |
|--------|----------------------|-------------------|
| Downloads | ~165K | ~6.5M (40x) |
| Last updated | Dec 2025 | Feb 2026 |
| `unsafe_code` | Allowed | `#![forbid(unsafe_code)]` |
| Heavy deps | `ring` (C/asm) | None (pure Rust via `ed25519-compact`) |
| API style | Generic type-driven builder | Simple function calls + Claims struct |

---

## Dependencies

### New Dependencies for `firma-core/Cargo.toml`

| Crate | Version | Features | Purpose |
|-------|---------|----------|---------|
| `pasetors` | `0.7` | `std` (default) | PASETO v4.public token creation and verification |

### Workspace-Level Dependency Addition

```toml
# In root Cargo.toml [workspace.dependencies]
pasetors = "0.7"
```

### firma-core `Cargo.toml` Addition

```toml
# In [dependencies]
pasetors = { workspace = true }
```

### No Additional Dependencies

- `ed25519-compact` comes transitively through `pasetors` — no direct dependency needed.
- `serde_json` already in deps (for claims serialization).
- `chrono` already in deps (for timestamp handling).

---

## API Design

### `PasetoV4Signer`

```text
pub struct PasetoV4Signer {
    secret_key: AsymmetricSecretKey<V4>,  // pasetors key type (owned, 64 bytes)
}

impl PasetoV4Signer {
    pub fn new(secret_key_bytes: &[u8]) -> Result<Self, TokenError>
    // Validates key length (64 bytes), constructs pasetors key type.
    // Error: TokenError::Malformed if key is invalid.
}

impl TokenSigner for PasetoV4Signer {
    fn sign(&self, claims: &CapabilityClaims) -> Result<String, TokenError>
    // 1. Create pasetors::claims::Claims
    // 2. Set exp from claims.expires_at (ISO 8601)
    // 3. Set iat from claims.issued_at (ISO 8601)
    // 4. Add custom claims: token_id, agent_id, session_id, actions, resources, context_hash
    // 5. Call pasetors::public::sign(&self.secret_key, &claims, None, None)
    // 6. Return token string
}
```

### `PasetoV4Verifier`

```text
pub struct PasetoV4Verifier {
    public_key: AsymmetricPublicKey<V4>,  // pasetors key type (owned, 32 bytes)
}

impl PasetoV4Verifier {
    pub fn new(public_key_bytes: &[u8]) -> Result<Self, TokenError>
    // Validates key length (32 bytes), constructs pasetors key type.
    // Error: TokenError::Malformed if key is invalid.
}

impl TokenVerifier for PasetoV4Verifier {
    fn verify(&self, raw_token: &str) -> Result<CapabilityClaims, TokenError>
    // 1. Parse raw_token as UntrustedToken<Public, V4>
    //    → ParseFailure if not a valid PASETO token
    // 2. Create ClaimsValidationRules (default: validates exp, nbf, iat)
    // 3. Call pasetors::public::verify(&self.public_key, &untrusted, &rules, None, None)
    //    → SignatureInvalid if signature fails
    //    → Expired if exp validation fails
    // 4. Extract payload_claims()
    // 5. Deserialize custom claims into CapabilityClaims
    //    → Malformed if required fields missing
    // 6. Return CapabilityClaims
}
```

### Test Helper

```text
pub(crate) fn generate_test_keypair() -> (Vec<u8>, Vec<u8>)
// Returns (secret_key_bytes, public_key_bytes) for use in tests.
// Uses pasetors::keys::AsymmetricKeyPair::<V4>::generate().
// Only available in test builds (#[cfg(test)]).
```

---

## Error Conversion Strategy

All `pasetors` errors map to `TokenError` variants:

| pasetors Error | TokenError Variant | Context |
|---------------|-------------------|---------|
| Key construction error | `Malformed { reason }` | "invalid private/public key: {details}" |
| `Claims` building error | `Malformed { reason }` | "claims serialization failed: {details}" |
| `UntrustedToken::try_from` error | `ParseFailure { reason }` | "not a valid PASETO token: {details}" |
| `public::verify` signature error | `SignatureInvalid { reason }` | "PASETO signature verification failed: {details}" |
| `public::verify` expiry error | `Expired { token_id }` | Extract token_id from claims if available, else "unknown" |
| Missing custom claim | `Malformed { reason }` | "missing required claim: {field_name}" |
| Invalid claim type | `Malformed { reason }` | "invalid claim type for {field_name}: expected {type}" |

**Challenge**: `pasetors` returns a single `pasetors::errors::Error` type. We need to inspect the error message or kind to distinguish signature failure from expiry failure. The approach:

1. First attempt `public::verify` with default validation rules (includes exp check).
2. If it fails, check if the error is related to token expiry by inspecting the error.
3. Map accordingly.

**Alternative**: Disable automatic exp validation in `ClaimsValidationRules`, verify signature first, then manually check expiry. This gives precise error discrimination. This is the preferred approach.

**Revised Verify Flow**:
1. Parse `UntrustedToken` → `ParseFailure` on error
2. Create `ClaimsValidationRules` with time validation disabled
3. Call `public::verify` (signature check only) → `SignatureInvalid` on error
4. Extract claims from verified token
5. Manually check `exp` claim against `chrono::Utc::now()` → `Expired` if past
6. Deserialize custom claims → `Malformed` if missing/invalid
7. Return `CapabilityClaims`

This gives clean, precise error mapping without guessing from error messages.

---

## Claims Serialization / Deserialization

### Signing (Claims → PASETO)

```text
fn build_paseto_claims(claims: &CapabilityClaims) -> Result<pasetors::claims::Claims, TokenError>

1. Create Claims with custom expiration: Claims::new_expires_in(&duration)
   where duration = claims.expires_at - claims.issued_at
   BUT this doesn't set the right exp — we need the absolute time.

   Better: Create claims, then manually set exp and iat.
   - claims.expiration("2026-03-28T12:00:00+00:00")  → set exp
   - claims.issued_at("2026-03-28T11:00:00+00:00")   → set iat

2. Add custom claims via claims.add_additional():
   - "token_id" → String
   - "agent_id" → String
   - "session_id" → String
   - "actions" → JSON array (serde_json::to_value)
   - "resources" → JSON array (serde_json::to_value)
   - "context_hash" → String
```

### Verification (PASETO → Claims)

```text
fn extract_capability_claims(claims: &pasetors::claims::Claims) -> Result<CapabilityClaims, TokenError>

1. Extract each custom claim via claims.get_claim("field_name")
2. Parse string claims directly
3. Parse array claims via serde_json::from_value
4. Parse iat/exp back to DateTime<Utc> via chrono parsing
5. Return CapabilityClaims struct
```

---

## Security Design

| Concern | Approach |
|---------|----------|
| Key material handling | `pasetors` key types zeroize on drop. Signer/Verifier do not expose key bytes. |
| No unsafe code | `pasetors` uses `#![forbid(unsafe_code)]`, `firma-core` uses `#![deny(unsafe_code)]` |
| Error information leakage | Error messages include operation context but never key material or full token contents |
| Timing attacks | Ed25519 verification in `ed25519-compact` uses constant-time operations |

---

## NFR Implementation

| Requirement | Design Approach |
|-------------|-----------------|
| NFR-1: verify < 500µs | Ed25519 verify is ~60-100µs on modern hardware. JSON deserialization adds ~10-20µs. Well within budget. |
| NFR-1: sign < 1ms | Ed25519 sign is ~50-80µs. JSON serialization adds ~10-20µs. Well within budget. |
| NFR-2: No unsafe code | `pasetors` forbids unsafe, `firma-core` denies unsafe |
| NFR-3: No network I/O | Pure computation — key bytes provided at construction |

---

## Test Strategy (Preview)

Co-located tests in `paseto.rs` (`#[cfg(test)] mod tests`):

| Test | Category | Story |
|------|----------|-------|
| Round-trip: sign → verify → claims match | Functional | 003 |
| Expired token rejected | Functional | 002, 003 |
| Tampered token rejected | Functional | 002, 003 |
| Wrong public key rejected | Functional | 002, 003 |
| Malformed string rejected | Functional | 002, 003 |
| Empty string rejected | Functional | 002, 003 |
| Signer as `dyn TokenSigner` compiles | Object safety | 001 |
| Verifier as `dyn TokenVerifier` compiles | Object safety | 002 |
| Verify < 500µs (rough check with Instant) | Performance | 003 |
| Sign < 1ms (rough check with Instant) | Performance | 003 |
| Invalid key bytes rejected | Error handling | 001, 002 |
| Claims with empty actions/resources round-trip | Edge case | 001 |
| Claims with unicode agent_id round-trip | Edge case | 003 |

Full test details in Stage 5.
