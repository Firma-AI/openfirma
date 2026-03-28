---
id: 003-decision-and-errors
unit: 001-types-and-traits
intent: 002-core-types-shared-library
status: draft
priority: must
created: 2026-03-26T14:10:00Z
assigned_bolt: null
implemented: false
---

# Story: 003-decision-and-errors

## User Story

**As a** Firma component developer
**I want** a typed Decision enum with all enforcement reason codes, plus structured error types
**So that** enforcement outcomes are unambiguous and errors carry enough context for audit trails

## Acceptance Criteria

- [ ] **Given** the `Decision` enum, **When** I construct Allow, Deny, or Abort variants, **Then** they compile and can be matched exhaustively
- [ ] **Given** a `Deny` decision, **When** I access its `DenyReason`, **Then** I get one of the 11 reason codes (BudgetExceeded and RiskThreshold deferred per PR #5 review)
- [ ] **Given** any `DenyReason` variant, **When** I call `Display` on it, **Then** it returns a human-readable message
- [ ] **Given** a `TokenError`, **When** I construct any variant (ParseFailure, SignatureInvalid, Expired, Revoked, Malformed), **Then** it includes structured context fields (e.g., token_id)
- [ ] **Given** an `EvaluationError`, **When** I construct any variant (PolicyLoadFailure, ContextBuildFailure, InternalError), **Then** it includes a descriptive message
- [ ] **Given** any error type, **When** I use `thiserror` Display, **Then** it produces a useful error message

## Technical Notes

- `DenyReason` variants: TokenInvalid, TokenExpired, TokenRevoked, PolicyDenied, ScopeViolation, ToolNotInScope, MalformedRequest, AuthorityUnavailable, PolicyBundleStale, CredentialInjectionFailed, ConnectorTimeout. Deferred: BudgetExceeded, RiskThreshold (per PR #5 review — add back when budget/risk mechanisms exist)
- Error types follow coding standards pattern: `thiserror` derive, structured context fields, `?` propagation
- `TokenError` is used by `TokenVerifier::verify` return type
- `EvaluationError` is used by `PolicyEvaluator::evaluate` return type
- Consider implementing `From<TokenError>` for a top-level `FirmaError` if it aids ergonomics

## Dependencies

### Requires

- None (standalone types, though conceptually follows token and execution types)

### Enables

- 004-trait-interfaces (traits return these error types)

## Edge Cases

| Scenario | Expected Behavior |
| -------- | ----------------- |
| DenyReason used in logging | Display impl produces structured, grep-friendly output |
| Multiple error sources in EvaluationError | Use `#[from]` for common conversions where appropriate |
| Serialization of Decision for audit | Decision and DenyReason derive Serialize for audit emitter |

## Out of Scope

- HTTP status code mapping from Decision (Sidecar, intent 006)
- gRPC status mapping from errors (intent 003/005)
