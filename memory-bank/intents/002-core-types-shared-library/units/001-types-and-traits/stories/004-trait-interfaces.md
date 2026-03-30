---
id: 004-trait-interfaces
unit: 001-types-and-traits
intent: 002-core-types-shared-library
status: complete
priority: must
created: 2026-03-26T14:10:00.000Z
assigned_bolt: null
implemented: true
---

# Story: 004-trait-interfaces

## User Story

**As a** Firma component developer
**I want** well-defined trait interfaces for policy evaluation, token operations, and storage
**So that** I can implement them in later intents without modifying firma-core, and mock them in tests

## Acceptance Criteria

- [ ] **Given** the `TokenSigner` trait, **When** I define a struct that implements `sign(&self, claims: &CapabilityClaims) -> Result<String, TokenError>`, **Then** it compiles
- [ ] **Given** the `TokenVerifier` trait, **When** I define a struct that implements `verify(&self, raw_token: &str) -> Result<CapabilityClaims, TokenError>`, **Then** it compiles
- [ ] **Given** the `PolicyEvaluator` trait, **When** I define a struct that implements `evaluate(&self, context: &ExecutionContext) -> Result<Decision, EvaluationError>`, **Then** it compiles
- [ ] **Given** the `PolicyBundleStore` trait, **When** I define a struct that implements its methods (load_bundle, get_version, is_fresh), **Then** it compiles
- [ ] **Given** the `RevocationStore` trait, **When** I define a struct that implements `is_revoked` and `add_revocation`, **Then** it compiles
- [ ] **Given** any of the above traits, **When** I use it as `Box<dyn Trait>`, **Then** it compiles (object-safe)

## Technical Notes

- All traits must be object-safe — no associated types, no generic methods, no `Self` in return position
- `PolicyBundleStore` methods:
  - `load_bundle(&self) -> Result<PolicyBundle, EvaluationError>` — load current policy set
  - `get_version(&self) -> Option<String>` — current bundle version ID
  - `is_fresh(&self) -> bool` — whether bundle TTL is still valid
- `RevocationStore` methods:
  - `is_revoked(&self, token_id: &str) -> Result<bool, TokenError>` — check revocation
  - `add_revocation(&self, token_id: &str) -> Result<(), TokenError>` — record revocation
- `PolicyBundle` can be a simple opaque type or newtype for now — later intents will define its internals
- Consider whether traits need `Send + Sync` bounds for async runtime compatibility

## Dependencies

### Requires

- 001-capability-token-types (TokenSigner/Verifier use CapabilityClaims)
- 002-execution-types (PolicyEvaluator uses ExecutionContext)
- 003-decision-and-errors (traits return Decision, TokenError, EvaluationError)

### Enables

- Unit 002 stories (PASETO v4 implements TokenSigner/TokenVerifier)
- Intent 005 (Authority implements PolicyEvaluator, PolicyBundleStore)
- Intent 006 (Sidecar implements RevocationStore, uses PolicyEvaluator)

## Edge Cases

| Scenario | Expected Behavior |
| -------- | ----------------- |
| Trait used with dynamic dispatch (dyn) | Must compile — object safety is a hard requirement |
| Trait used in async context | Traits are sync; async wrappers are the caller's responsibility |
| Multiple implementations in same binary | Supported via dyn dispatch or generics |

## Out of Scope

- Concrete implementations of any trait (Units 002, intents 005/006)
- Async trait variants (can be added later if needed)
