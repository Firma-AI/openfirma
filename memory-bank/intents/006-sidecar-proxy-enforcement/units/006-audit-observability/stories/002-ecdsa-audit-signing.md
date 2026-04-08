---
id: 002-ecdsa-audit-signing
unit: 006-audit-observability
intent: 006-sidecar-proxy-enforcement
status: draft
priority: must
created: 2026-04-05T12:00:00Z
assigned_bolt: null
implemented: false
---

# Story: 002-ecdsa-audit-signing

## User Story

**As an** auditor
**I want** every audit event signed with ECDSA so that I can verify event integrity without access to the Sidecar
**So that** audit trails are tamper-evident and independently verifiable

## Acceptance Criteria

- [ ] **Given** a fully populated ExecutionEvent (all fields except `signature`), **When** the signing layer processes the event, **Then** an ECDSA signature is computed over all event fields (excluding the `signature` field itself) and stored in the `signature` field
- [ ] **Given** a signed ExecutionEvent and the Sidecar's audit signing public key, **When** an external auditor verifies the signature, **Then** the verification succeeds, confirming event integrity
- [ ] **Given** a signed ExecutionEvent where any field has been tampered with, **When** an external auditor verifies the signature, **Then** the verification fails
- [ ] **Given** the audit signing keypair, **When** compared to the CA keypair used for TLS MITM interception, **Then** they are distinct keys (separate key purposes)
- [ ] **Given** audit event signing on the enforcement hot path, **When** signing occurs, **Then** it does not block or measurably delay the enforcement decision (signing happens after the decision, before async emission)

## Technical Notes

- Use the `p256` crate (NIST P-256 / secp256r1) or `ecdsa` crate for ECDSA signing — P-256 is widely supported for verification in external tooling
- Signing input: canonical JSON serialization of all ExecutionEvent fields except `signature`, then SHA-256 hash, then ECDSA sign
- Canonical serialization is critical for deterministic signing — use a deterministic JSON serialization (sorted keys, no whitespace variance). Consider `serde_json::to_string` with a custom serializer that sorts keys, or define a canonical byte representation
- The audit signing keypair should be:
  - Generated at Sidecar startup if not present at the configured path
  - Persisted to a configurable path (separate from the CA keypair)
  - Public key exported in PEM or DER format for distribution to auditors
- Key management configuration (approximate TOML):
  ```toml
  [audit]
  signing_key_path = "/var/firma/audit-signing-key.pem"
  signing_pub_key_path = "/var/firma/audit-signing-pub.pem"
  ```
- Signing latency target: < 50us per event (P-256 ECDSA sign is typically ~10-30us on modern hardware)
- The signing step occurs after the enforcement decision is made but before the event is handed off to the async sink channel — it is on the critical path between decision and emission, not on the enforcement decision path itself
- Signature encoding: base64url (RFC 4648 §5) for compact JSON representation

## Dependencies

### Requires

- 001-execution-event-schema (provides the ExecutionEvent struct with the `signature` field)

### Enables

- 003-audit-sinks (emits signed events to sinks)
- External audit verification tooling (verifies signatures using the public key)

## Edge Cases

| Scenario | Expected Behavior |
| -------- | ----------------- |
| Signing key file does not exist at startup | Generate a new keypair, persist to configured path, export public key; log the public key fingerprint |
| Signing key file exists but is corrupt or unreadable | Fail-fast at startup with clear error message (do not generate a new key silently) |
| Signing key file permissions are too open (world-readable) | Log warning at startup; do not fail (operator responsibility) |
| Event field contains non-UTF8 binary data | Canonical serialization handles binary fields via base64 encoding before signing |
| Concurrent events signed simultaneously | Signing is stateless (no mutable state beyond the key); safe for concurrent use via `Arc<SigningKey>` |
| Signing operation fails at runtime (should be extremely rare) | Event emitted with empty/zero signature; error logged; event is not suppressed |
| Clock skew between event creation and signing | Irrelevant — signing uses the event's `timestamp_ns` field, not current time |
| Auditor has wrong public key version (key was rotated) | Signature verification fails; auditor must use the public key corresponding to the signing period; key rotation strategy is post-V1 |

## Out of Scope

- Key rotation mechanisms (V1 uses a single long-lived audit signing keypair)
- Hardware security module (HSM) integration for key storage
- Key distribution to auditors (operator responsibility; public key is exported to a file)
- Certificate-based signing (raw ECDSA keypair, not X.509 certificate)
- Signature verification tooling (external; Sidecar only produces signatures)
- Batch signing or signature aggregation
