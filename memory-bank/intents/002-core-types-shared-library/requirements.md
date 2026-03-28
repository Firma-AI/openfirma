---
intent: 002-core-types-shared-library
phase: inception
status: complete
created: 2026-03-26T14:00:00Z
updated: 2026-03-26T14:10:00Z
---

# Requirements: Core Types & Shared Library

## Intent Overview

Build the real `firma-core` crate — the shared foundation used by both `firma-sidecar` and `firma-authority`. Includes capability token types and PASETO v4 signing/verification, execution types (Envelope, Context), policy evaluation contract (trait only, no Cedar dependency), storage trait interfaces, error types, and the Decision enum with all enforcement reason codes.

## Business Goals

| Goal | Success Metric | Priority |
| ---- | -------------- | -------- |
| Stable shared types for all downstream crates | `firma-sidecar` and `firma-authority` depend on `firma-core` with no type conflicts | Must |
| Token operations meet Stage 1 latency budget | PASETO v4 verify < 500µs, sign < 1ms | Must |
| Clean crate boundary — no Cedar dependency | `firma-core` Cargo.toml has no `cedar-policy` entry | Must |
| Trait-based extensibility for storage and evaluation | Later intents implement traits without modifying firma-core | Must |

---

## Functional Requirements

### FR-1: Capability Claims Type
- **Description**: Define a `CapabilityClaims` struct representing the payload of a capability token — token ID, agent ID, session ID, action set, resource scope, issued-at, expires-at, and integrity hash of the Cedar context used at issuance
- **Acceptance Criteria**: Struct compiles; all fields from the component reference Section 5 / 3.5 are represented; struct derives `Debug`, `Clone`, `Serialize`, `Deserialize`
- **Priority**: Must

### FR-2: Token Lifecycle States
- **Description**: Define a `TokenState` enum representing capability token lifecycle: Issued, Active, InUse, Expired, Revoked, Aborted (per component reference Section 8)
- **Acceptance Criteria**: Enum compiles; all six states from the capability lifecycle are represented; transitions are documented in code comments
- **Priority**: Must

### FR-3: Token Signing and Verification Traits
- **Description**: Define `TokenSigner` and `TokenVerifier` traits that abstract over token format. `TokenSigner::sign` takes `CapabilityClaims` and returns a serialized token string. `TokenVerifier::verify` takes a raw token string and returns validated `CapabilityClaims` or a typed error.
- **Acceptance Criteria**: Traits compile; they are format-agnostic (no PASETO/JWT types in the signature); both traits are object-safe for dynamic dispatch
- **Priority**: Must

### FR-4: PASETO v4 Implementation
- **Description**: Implement `TokenSigner` and `TokenVerifier` for PASETO v4 using `rusty_paseto`. Signing uses Ed25519 private key, verification uses Ed25519 public key. Token payload carries all `CapabilityClaims` fields.
- **Acceptance Criteria**: Round-trip test passes (sign → verify → claims match); expired token is rejected; tampered token is rejected; invalid key is rejected
- **Priority**: Must

### FR-5: Execution Envelope Type
- **Description**: Define an `ExecutionEnvelope` struct with four fields: intent (action type, target resource, action-specific parameters), capability (token reference), metadata (session ID, agent ID, timestamp, trace ID, budget consumed), provenance (optional, nullable in V1)
- **Acceptance Criteria**: Struct compiles; all fields from component reference Section 4.2 are represented; provenance is `Option<T>`
- **Priority**: Must

### FR-6: Execution Context Type
- **Description**: Define an `ExecutionContext` struct representing the attributes used during policy evaluation — agent identity, action, resource, budget remaining, risk score, session metadata, and any additional context attributes needed for Cedar evaluation
- **Acceptance Criteria**: Struct compiles; fields cover the inputs to Stage 2 as described in domain-design-decisions.md; can be constructed from an `ExecutionEnvelope`
- **Priority**: Must

### FR-7: Decision Enum
- **Description**: Define a `Decision` enum with three variants: `Allow`, `Deny { reason: DenyReason }`, `Abort { reason: String }`. Define `DenyReason` as a typed enum covering all reason codes from the domain design decisions (TokenInvalid, TokenExpired, TokenRevoked, PolicyDenied, BudgetExceeded, ScopeViolation, RiskThreshold, ToolNotInScope, MalformedRequest, AuthorityUnavailable, PolicyBundleStale, CredentialInjectionFailed, ConnectorTimeout)
- **Acceptance Criteria**: Enum compiles; all reason codes from domain-design-decisions.md are present; `DenyReason` implements `Display` with human-readable messages
- **Priority**: Must

### FR-8: Policy Evaluator Trait
- **Description**: Define a `PolicyEvaluator` trait with a single method: `evaluate(&self, context: &ExecutionContext) -> Result<Decision, EvaluationError>`. No Cedar dependency — this is a contract that Cedar implementations will fulfill in later intents.
- **Acceptance Criteria**: Trait compiles; no `cedar-policy` crate in firma-core dependencies; trait is object-safe
- **Priority**: Must

### FR-9: Storage Traits
- **Description**: Define trait interfaces for `PolicyBundleStore` (load policy bundle, get bundle version, check bundle TTL) and `RevocationStore` (check if token is revoked by token ID, add revocation). No implementations — trait definitions only.
- **Acceptance Criteria**: Traits compile; method signatures cover the operations described in component reference Section 4.5 (policy bundle cache, revocation cache); no concrete implementations in firma-core
- **Priority**: Must

### FR-10: Error Types
- **Description**: Define `firma-core` error types using `thiserror`: `TokenError` (parse failure, signature invalid, expired, revoked, malformed), `EvaluationError` (policy load failure, context build failure, internal error). Follow the coding standards error handling pattern.
- **Acceptance Criteria**: Error enums compile; all variants include structured context (token_id, reason) for audit trail; `thiserror` derives `Error` and `Display`; no `.unwrap()` or `.expect()` in library code
- **Priority**: Must

---

## Non-Functional Requirements

### NFR-1: Performance — Token Operations

| Requirement | Metric | Target |
| ----------- | ------ | ------ |
| PASETO v4 sign | Wall-clock time | < 1ms |
| PASETO v4 verify | Wall-clock time | < 500µs |

These targets ensure Stage 1 can meet its < 1ms p95 budget.

### NFR-2: No Unsafe Code

| Requirement | Standard | Notes |
| ----------- | -------- | ----- |
| Memory safety | `#![deny(unsafe_code)]` | Per coding standards — no unsafe blocks |

### NFR-3: Zero External Network Dependencies

| Requirement | Standard | Notes |
| ----------- | -------- | ----- |
| Offline capability | All firma-core types and crypto must work without network access | Pure computation, no I/O |

---

## Constraints

### Technical Constraints

**Project-wide standards**: Coding standards, tech stack, and system architecture from `memory-bank/standards/` apply.

**Intent-specific constraints**:

- `firma-core` must not depend on `cedar-policy` — Cedar is an implementation detail of later intents
- JWT RS256 support is deferred — trait is defined, only PASETO v4 is implemented
- Storage traits are interfaces only — no concrete implementations
- Must use `rusty_paseto` for PASETO v4 and `thiserror` for errors (per tech stack)

### Business Constraints

- This crate is the dependency of every other crate — API stability matters from day one

---

## Assumptions

| Assumption | Risk if Invalid | Mitigation |
| ---------- | --------------- | ---------- |
| `rusty_paseto` supports PASETO v4 with Ed25519 signing | Need alternative crate or manual implementation | Verify crate capabilities before construction |
| `CapabilityClaims` fields are stable across intents 005/006 | Refactoring shared types breaks downstream | Careful field selection based on component reference |
| Object-safe traits are sufficient (no associated types needed) | May need to change trait design for async or generics | Start simple, refactor if construction reveals limitations |
