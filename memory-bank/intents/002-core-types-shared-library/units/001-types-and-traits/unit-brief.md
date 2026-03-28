---
unit: 001-types-and-traits
intent: 002-core-types-shared-library
phase: inception
status: ready
created: 2026-03-26T14:10:00Z
updated: 2026-03-26T14:10:00Z
---

# Unit Brief: Types and Traits

## Purpose

Define all shared domain types, error types, and trait interfaces that form the public API surface of `firma-core`. This is the foundation that every other crate in the workspace depends on. Pure types and contracts — no crypto, no I/O.

## Scope

### In Scope

- `CapabilityClaims` struct and `TokenState` enum
- `ExecutionEnvelope` and `ExecutionContext` structs
- `Decision` enum with `DenyReason`
- `TokenError` and `EvaluationError` error enums
- `PolicyEvaluator`, `TokenSigner`, `TokenVerifier` traits
- `PolicyBundleStore`, `RevocationStore` traits
- Unit tests for construction, Display impls, trait object safety

### Out of Scope

- PASETO v4 implementation (Unit 002)
- JWT RS256 implementation (deferred from V1)
- Cedar dependency or evaluation logic (intents 005/006)
- Concrete storage implementations (intents 005/006)

---

## Assigned Requirements

| FR | Requirement | Priority |
| -- | ----------- | -------- |
| FR-1 | Capability Claims Type | Must |
| FR-2 | Token Lifecycle States | Must |
| FR-3 | Token Signing and Verification Traits | Must |
| FR-5 | Execution Envelope Type | Must |
| FR-6 | Execution Context Type | Must |
| FR-7 | Decision Enum | Must |
| FR-8 | Policy Evaluator Trait | Must |
| FR-9 | Storage Traits | Must |
| FR-10 | Error Types | Must |

---

## Domain Concepts

### Key Entities

| Entity | Description | Attributes |
| ------ | ----------- | ---------- |
| CapabilityClaims | Payload of a signed capability token | token_id, agent_id, session_id, actions, resources, issued_at, expires_at, context_hash |
| TokenState | Lifecycle state of a capability token | Issued, Active, InUse, Expired, Revoked, Aborted |
| ExecutionEnvelope | Core protocol unit wrapping each outbound call | intent, capability, metadata, provenance |
| ExecutionContext | Attributes used during policy evaluation | agent_id, action, resource, budget_remaining, risk_score, session metadata |
| Decision | Outcome of policy evaluation | Allow, Deny(reason), Abort(reason) |
| DenyReason | Typed reason code for denial | 13 variants covering all enforcement reasons |

### Key Operations

| Operation | Description | Inputs | Outputs |
| --------- | ----------- | ------ | ------- |
| TokenSigner::sign | Serialize and sign capability claims | CapabilityClaims | Result<String, TokenError> |
| TokenVerifier::verify | Parse, verify signature, validate claims | raw token string | Result<CapabilityClaims, TokenError> |
| PolicyEvaluator::evaluate | Evaluate policy against execution context | ExecutionContext | Result<Decision, EvaluationError> |
| RevocationStore::is_revoked | Check if a token ID has been revoked | token_id | Result<bool> |
| PolicyBundleStore::load_bundle | Load the current policy bundle | — | Result<PolicyBundle> |

---

## Story Summary

| Metric | Count |
| ------ | ----- |
| Total Stories | 4 |
| Must Have | 4 |
| Should Have | 0 |
| Could Have | 0 |

### Stories

| Story ID | Title | Priority | Status |
| -------- | ----- | -------- | ------ |
| 001-capability-token-types | Capability Claims and Token State | Must | Planned |
| 002-execution-types | Execution Envelope and Context | Must | Planned |
| 003-decision-and-errors | Decision, DenyReason, and Error Types | Must | Planned |
| 004-trait-interfaces | All trait definitions | Must | Planned |

---

## Dependencies

### Depends On

None — this is the foundation unit.

### Depended By

| Unit | Reason |
| ---- | ------ |
| 002-paseto-v4 | Needs CapabilityClaims, TokenSigner, TokenVerifier, TokenError |

### External Dependencies

| System | Purpose | Risk |
| ------ | ------- | ---- |
| serde | Serialization derives | Low — stable, widely used |
| thiserror | Error derives | Low — stable, widely used |
| chrono | Timestamp types | Low — stable |

---

## Technical Context

### Suggested Technology

Standard Rust library crate. No framework. Dependencies: `serde`, `serde_json`, `thiserror`, `chrono`.

### Integration Points

None — pure types and traits. All integration happens in downstream crates.

### Data Storage

None — no persistence, no I/O.

---

## Constraints

- No `cedar-policy` dependency
- No I/O or async in this unit
- All public types must derive `Debug`, `Clone`
- Error types must use `thiserror`
- Must pass `deny(unwrap_used)`, `deny(expect_used)`, `deny(unsafe_code)`

---

## Success Criteria

### Functional

- [ ] All types from FR-1 through FR-10 compile and are publicly exported
- [ ] All traits are object-safe (can be used as `dyn Trait`)
- [ ] `ExecutionContext` can be constructed from `ExecutionEnvelope` fields

### Non-Functional

- [ ] Zero `unsafe` code
- [ ] Passes all workspace Clippy lints

### Quality

- [ ] Unit tests for type construction and Display impls
- [ ] Trait object-safety verified in tests
- [ ] All acceptance criteria from assigned FRs met

---

## Bolt Suggestions

| Bolt | Type | Stories | Objective |
| ---- | ---- | ------- | --------- |
| 002-types-and-traits | DDD | 001, 002, 003, 004 | All types and traits in one bolt — tightly coupled, low complexity |

---

## Notes

All 4 stories are tightly coupled — types reference each other (e.g., `Decision` uses `DenyReason`, traits use `ExecutionContext` and `CapabilityClaims`). Best built in a single bolt to avoid partial compilation issues.
