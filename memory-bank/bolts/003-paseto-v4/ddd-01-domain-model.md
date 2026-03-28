---
unit: 002-paseto-v4
bolt: 003-paseto-v4
stage: model
status: complete
updated: 2026-03-28T10:50:00Z
---

# Static Model — PASETO v4

## Bounded Context

**Token Cryptography** — implements the `TokenSigner` and `TokenVerifier` trait contracts defined in Unit 001 using PASETO v4.public tokens with Ed25519 signatures. This context is purely computational — it takes claims in, produces signed tokens out, and vice versa. No I/O, no storage, no policy logic.

---

## Domain Entities

### PasetoV4Signer (Story 001)

Signs `CapabilityClaims` into PASETO v4.public tokens using an Ed25519 private key.

| Property | Type | Business Rules |
|----------|------|----------------|
| `private_key` | Ed25519 secret key (64 bytes: 32-byte seed + 32-byte public key) | Held for the lifetime of the signer. Not cloneable — single owner. |

**Implements**: `TokenSigner`

**Operations**:

| Method | Signature | Description |
|--------|-----------|-------------|
| `new` | `fn new(private_key_bytes: &[u8]) -> Result<Self, TokenError>` | Construct from raw 64-byte Ed25519 key. Returns error if key is invalid. |
| `sign` | `fn sign(&self, claims: &CapabilityClaims) -> Result<String, TokenError>` | Serialize claims to JSON, embed as PASETO payload, sign with Ed25519, return token string. |

**Sign Process**:
1. Serialize `CapabilityClaims` fields into PASETO claims (custom claims for Firma-specific fields).
2. Set registered claims: `exp` (from `claims.expires_at`), `iat` (from `claims.issued_at`).
3. Sign with Ed25519 private key → produce `v4.public.{base64url-encoded-payload-and-signature}`.
4. Return the token string.

**Error Mapping**:
- Invalid key bytes → `TokenError::Malformed { reason: "invalid private key" }`
- Serialization failure → `TokenError::Malformed { reason: ... }`

---

### PasetoV4Verifier (Story 002)

Verifies PASETO v4.public tokens and extracts `CapabilityClaims` using an Ed25519 public key.

| Property | Type | Business Rules |
|----------|------|----------------|
| `public_key` | Ed25519 public key (32 bytes) | Held for the lifetime of the verifier. Can be cloned (public data). |

**Implements**: `TokenVerifier`

**Operations**:

| Method | Signature | Description |
|--------|-----------|-------------|
| `new` | `fn new(public_key_bytes: &[u8]) -> Result<Self, TokenError>` | Construct from raw 32-byte Ed25519 public key. Returns error if key is invalid. |
| `verify` | `fn verify(&self, raw_token: &str) -> Result<CapabilityClaims, TokenError>` | Parse token, verify signature, check expiry, deserialize claims, return `CapabilityClaims`. |

**Verify Process**:
1. Parse the raw token string as a PASETO v4.public token.
2. Verify the Ed25519 signature using the public key.
3. Validate the `exp` claim against the current time → reject if expired.
4. Deserialize the payload claims into `CapabilityClaims`.
5. Return the validated claims.

**Error Mapping**:
- Invalid key bytes → `TokenError::Malformed { reason: "invalid public key" }`
- Not a valid PASETO token → `TokenError::ParseFailure { reason: ... }`
- Signature verification fails → `TokenError::SignatureInvalid { reason: ... }`
- Token expired (`exp` in the past) → `TokenError::Expired { token_id }` (extract token_id from claims if possible, else use "unknown")
- Missing required claims → `TokenError::Malformed { reason: "missing field: ..." }`

---

## Value Objects

### Ed25519 Key Pair (Test Helper)

For tests, a helper function generates a fresh Ed25519 key pair.

| Property | Type | Constraints |
|----------|------|-------------|
| `secret` | 64 bytes (seed + public key) | Random, valid Ed25519 key pair |
| `public` | 32 bytes | Derived from secret key |

This is NOT a production entity — production key management is a deployment concern (out of scope).

---

## Claims Mapping

How `CapabilityClaims` fields map to PASETO claims:

| CapabilityClaims Field | PASETO Claim | Claim Type |
|------------------------|-------------|------------|
| `token_id` | `token_id` | Custom |
| `agent_id` | `agent_id` | Custom |
| `session_id` | `session_id` | Custom |
| `actions` | `actions` | Custom (JSON array) |
| `resources` | `resources` | Custom (JSON array) |
| `issued_at` | `iat` | Registered (ISO 8601) |
| `expires_at` | `exp` | Registered (ISO 8601) |
| `context_hash` | `context_hash` | Custom |

**Registered claims** (`iat`, `exp`) are used by the PASETO library for automatic validation. **Custom claims** are Firma-specific and stored as additional payload fields.

---

## Domain Events

None — this unit produces and validates tokens. Token lifecycle events (issued, revoked, expired) are emitted by the Authority and Sidecar in later intents.

---

## Domain Services

None beyond the two entities above. `PasetoV4Signer` and `PasetoV4Verifier` are the service implementations themselves.

---

## Repository Interfaces

None — no persistence. Keys are provided at construction time.

---

## Ubiquitous Language

| Term | Definition |
|------|------------|
| **PASETO v4.public** | Token format using Ed25519 public-key signatures. Payload is visible but tamper-proof. |
| **Ed25519** | Elliptic-curve signature scheme. 32-byte public key, 64-byte secret key (seed + public). |
| **Registered Claim** | Standard PASETO claim (`exp`, `iat`, `nbf`) with built-in validation support. |
| **Custom Claim** | Application-specific claim embedded in the PASETO payload (e.g., `token_id`, `agent_id`). |
| **Round-trip** | Sign claims → produce token → verify token → recover identical claims. |

---

## Story Coverage Matrix

| Story | Entities/Concepts Covered | Status |
|-------|--------------------------|--------|
| 001-paseto-signer | `PasetoV4Signer`, signing process, error mapping, claims serialization | Covered |
| 002-paseto-verifier | `PasetoV4Verifier`, verification process, error mapping, expiry check, claims deserialization | Covered |
| 003-token-round-trip-tests | Round-trip, expired, tampered, wrong key, malformed, performance | Covered (test scenarios defined) |

---

## Crate Selection Note

The tech stack specifies `rusty_paseto`. Research during construction reveals `pasetors` (0.7.8) may be a stronger choice (40x more downloads, `forbid(unsafe_code)`, no `ring` dependency). This decision will be formalized in Stage 3 (ADR Analysis).
