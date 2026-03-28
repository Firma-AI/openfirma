---
intent: 002-core-types-shared-library
phase: inception
status: units-decomposed
updated: 2026-03-26T14:10:00Z
---

# Core Types & Shared Library - Unit Decomposition

## Units Overview

This intent decomposes into 2 units of work:

### Unit 1: 001-types-and-traits

**Description**: Define all shared domain types (ExecutionEnvelope, ExecutionContext, CapabilityClaims, Decision, DenyReason, TokenState), error types (TokenError, EvaluationError), and trait interfaces (PolicyEvaluator, TokenSigner, TokenVerifier, PolicyBundleStore, RevocationStore). Pure types and contracts — no crypto, no external dependencies beyond serde/thiserror/chrono.

**Stories**:

- Story 001: Capability token types (CapabilityClaims, TokenState)
- Story 002: Execution types (ExecutionEnvelope, ExecutionContext)
- Story 003: Decision and error types (Decision, DenyReason, TokenError, EvaluationError)
- Story 004: Trait interfaces (PolicyEvaluator, TokenSigner, TokenVerifier, PolicyBundleStore, RevocationStore)

**Deliverables**:

- Rust module files in `firma-core/src/` with all public types and traits
- Unit tests for type construction, Display impls, and trait object safety

**Dependencies**:

- Depends on: None
- Depended by: 002-paseto-v4

**Estimated Complexity**: M

### Unit 2: 002-paseto-v4

**Description**: Implement `TokenSigner` and `TokenVerifier` for PASETO v4 using `rusty_paseto` with Ed25519 keys. Includes key generation helpers for testing, round-trip sign/verify, and rejection of expired/tampered/invalid tokens.

**Stories**:

- Story 001: PASETO v4 signer implementation
- Story 002: PASETO v4 verifier implementation
- Story 003: Token round-trip and rejection tests

**Deliverables**:

- `PasetoV4Signer` and `PasetoV4Verifier` structs implementing the traits from Unit 1
- Comprehensive tests: round-trip, expired, tampered, wrong key, malformed

**Dependencies**:

- Depends on: 001-types-and-traits (needs CapabilityClaims, TokenSigner, TokenVerifier, TokenError)
- Depended by: Intent 005 (Authority token generation), Intent 006 (Sidecar Stage 1 validation)

**Estimated Complexity**: M

## Unit Dependency Graph

```text
[001-types-and-traits] ──> [002-paseto-v4]
```

## Execution Order

1. Unit 001: types-and-traits (foundation — all types and traits)
2. Unit 002: paseto-v4 (implements token traits from Unit 1)
