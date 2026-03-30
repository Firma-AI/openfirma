---
unit: 001-types-and-traits
bolt: 002-types-and-traits
stage: model
status: complete
updated: 2026-03-28T10:05:00Z
---

# Static Model — Types and Traits

## Bounded Context

**Core Types** — the shared type foundation for the Firma workspace. This bounded context defines the vocabulary (structs, enums, traits, errors) that `firma-sidecar` and `firma-authority` both depend on. It contains zero I/O, zero crypto implementation, and zero Cedar dependency. Every type here is a pure data structure or a trait contract fulfilled by downstream crates.

---

## Domain Entities

### CapabilityClaims (Story 001)

The payload carried inside a signed capability token. Represents the authority's grant to an agent for a scoped set of actions and resources within a session.

| Property | Type | Business Rules |
|----------|------|----------------|
| `token_id` | `String` | Globally unique identifier for this token. Used for revocation lookups. |
| `agent_id` | `String` | Identity of the agent this token was issued to. |
| `session_id` | `String` | Session within which this token is valid. |
| `actions` | `Vec<String>` | Allowed action set (e.g., `["http:GET", "tool:execute"]`). May be empty — Authority decides scope. |
| `resources` | `Vec<String>` | Resource scope (e.g., `["https://api.example.com/*"]`). May be empty. |
| `issued_at` | `DateTime<Utc>` | When the Authority issued this token. |
| `expires_at` | `DateTime<Utc>` | When this token expires. Validation enforced by `TokenVerifier`, not at construction. |
| `context_hash` | `String` | Hex-encoded SHA-256 of the Cedar context snapshot at issuance time. Integrity anchor. |

**Derives**: `Debug`, `Clone`, `Serialize`, `Deserialize`, `PartialEq`

**Rules**:
- No field-level validation at construction time — validation is the verifier's responsibility.
- Empty `actions`/`resources` are valid (Authority may issue open-scope tokens).
- `expires_at` may be in the past at construction time (for testing and deserialization).

---

### TokenState (Story 001)

Lifecycle state of a capability token as it moves through the system.

| Variant | Description |
|---------|-------------|
| `Issued` | Token created by Authority, not yet delivered to agent. |
| `Active` | Token delivered to agent, available for use. |
| `InUse` | Token currently attached to an in-flight execution. |
| `Expired` | Token TTL has elapsed. Terminal state. |
| `Revoked` | Token explicitly revoked by Authority or policy. Terminal state. |
| `Aborted` | Token invalidated due to policy abort. Terminal state. |

**Derives**: `Debug`, `Clone`, `PartialEq`, `Eq`, `Serialize`, `Deserialize`

**Rules**:
- Terminal states (`Expired`, `Revoked`, `Aborted`) cannot transition to any other state.
- State transitions are documented via code comments but not enforced at the type level (enforcement is the caller's responsibility).

---

### ExecutionEnvelope (Story 002)

The core protocol unit wrapping each outbound agent call. Built by the Sidecar when intercepting an agent's request.

| Property | Type | Business Rules |
|----------|------|----------------|
| `intent` | `ExecutionIntent` | Typed action parameters describing what the agent wants to do. |
| `capability` | `String` | Raw signed token string (not parsed claims — parsing happens in Stage 1 of the enforcement pipeline). |
| `metadata` | `RequestMetadata` | Session and request metadata for correlation and audit. |

**Derives**: `Debug`, `Clone`, `Serialize`, `Deserialize`

**Rules**:
- No `provenance` field (deferred per PR #5 review — add back when designed).
- No `budget_consumed` or `risk_score` (deferred per PR #5 review).
- `capability` is an opaque string — the Sidecar does not parse it before building the envelope.

---

### ExecutionIntent (Story 002)

Typed description of the action an agent intends to perform. Uses an enum to prevent injection via untyped maps.

| Variant | Fields | Description |
|---------|--------|-------------|
| `Http(HttpParams)` | method, url, headers | Outbound HTTP request |
| `DbQuery(DbQueryParams)` | statement, db_name, read_only | Database query |
| `ToolUse(ToolUseParams)` | tool_name, input | Tool/function invocation |

**Derives**: `Debug`, `Clone`, `Serialize`, `Deserialize`

**Rules**:
- Typed enum enforced — no generic `HashMap<String, Value>` for action params (injection risk per PR #5).
- New action types are added as new enum variants in future intents.

---

### RequestMetadata (Story 002)

Correlation and audit metadata attached to every execution envelope.

| Property | Type | Business Rules |
|----------|------|----------------|
| `session_id` | `String` | Session this request belongs to. |
| `agent_id` | `String` | Agent that initiated this request. |
| `timestamp` | `DateTime<Utc>` | When the request was intercepted. |
| `trace_id` | `Option<String>` | Optional distributed tracing correlation ID. |

**Derives**: `Debug`, `Clone`, `Serialize`, `Deserialize`

---

### ExecutionContext (Story 002)

The flattened attribute set consumed by Stage 2 (policy evaluation). Built from `ExecutionEnvelope` fields plus Sidecar-local state.

| Property | Type | Business Rules |
|----------|------|----------------|
| `agent_id` | `String` | From envelope metadata. |
| `action` | `String` | Derived from intent (e.g., `"http:GET"`, `"tool:execute"`). |
| `resource` | `String` | Target resource derived from intent (e.g., URL, DB name, tool name). |
| `session_id` | `String` | From envelope metadata. |
| `token_id` | `String` | From parsed capability claims. |
| `token_actions` | `Vec<String>` | Allowed actions from capability claims — for scope checks. |
| `token_resources` | `Vec<String>` | Allowed resources from capability claims — for scope checks. |

**Derives**: `Debug`, `Clone`, `Serialize`, `Deserialize`

**Rules**:
- No `budget_remaining` or `risk_score` (deferred per PR #5).
- `action` and `resource` are derived strings — the derivation logic lives in the Sidecar, not here.
- A `From<(&ExecutionEnvelope, &CapabilityClaims)>` conversion or builder pattern should be provided.

---

## Value Objects

| Value Object | Properties | Constraints |
|--------------|------------|-------------|
| `HttpParams` | `method: String`, `url: String`, `headers: HashMap<String, String>` | `method` should be a valid HTTP method; no validation at type level. |
| `DbQueryParams` | `statement: String`, `db_name: String`, `read_only: bool` | `read_only` is a hint for policy — not enforced at type level. |
| `ToolUseParams` | `tool_name: String`, `input: serde_json::Value` | `input` is a JSON value — tool-specific schema validated downstream. |
| `PolicyBundle` | Opaque newtype — internals defined by later intents | Placeholder for the set of loaded policies. Not empty-constructible — must be loaded via `PolicyBundleStore`. |

All value objects derive `Debug`, `Clone`, `Serialize`, `Deserialize`.

---

## Aggregates

This bounded context has no true aggregates with invariants. The types are standalone data carriers. The aggregate-like coordination (e.g., "token + state + revocation check") happens in the Sidecar and Authority binaries, not in `firma-core`.

---

## Domain Events

This unit defines no domain events. Events are emitted by the binaries (`firma-sidecar` enforcement pipeline, `firma-authority` token lifecycle) in later intents. The types here are the *payloads* those events will carry.

---

## Domain Services (Trait Contracts) (Story 004)

These are trait interfaces — no implementations in this unit.

### TokenSigner

| Method | Signature | Description |
|--------|-----------|-------------|
| `sign` | `fn sign(&self, claims: &CapabilityClaims) -> Result<String, TokenError>` | Serialize and cryptographically sign capability claims into a token string. |

**Rules**: Object-safe. Format-agnostic (no PASETO/JWT in signature). Implementation in Unit 002.

### TokenVerifier

| Method | Signature | Description |
|--------|-----------|-------------|
| `verify` | `fn verify(&self, raw_token: &str) -> Result<CapabilityClaims, TokenError>` | Parse, verify signature, validate expiry, and return claims. |

**Rules**: Object-safe. Must reject expired tokens. Must reject tampered tokens. Implementation in Unit 002.

### PolicyEvaluator

| Method | Signature | Description |
|--------|-----------|-------------|
| `evaluate` | `fn evaluate(&self, context: &ExecutionContext) -> Result<Decision, EvaluationError>` | Evaluate policy rules against the execution context and return an enforcement decision. |

**Rules**: Object-safe. No Cedar dependency in firma-core — this is a contract. Implementation in intent 005/006.

### PolicyBundleStore

| Method | Signature | Description |
|--------|-----------|-------------|
| `load_bundle` | `fn load_bundle(&self) -> Result<PolicyBundle, EvaluationError>` | Load the current policy bundle from storage/cache. |
| `get_version` | `fn get_version(&self) -> Option<String>` | Return the current bundle version ID, if known. |
| `is_fresh` | `fn is_fresh(&self) -> bool` | Whether the bundle TTL is still valid. |

**Rules**: Object-safe. No I/O assumptions in the trait — implementations decide sync vs async wrapping.

### RevocationStore

| Method | Signature | Description |
|--------|-----------|-------------|
| `is_revoked` | `fn is_revoked(&self, token_id: &str) -> Result<bool, TokenError>` | Check if a token has been revoked. |
| `add_revocation` | `fn add_revocation(&self, token_id: &str) -> Result<(), TokenError>` | Record a token revocation. |

**Rules**: Object-safe. Implementation in intent 005/006 (Authority and Sidecar cache).

---

## Error Types (Story 003)

### TokenError

Errors from token signing, verification, and revocation operations.

| Variant | Context Fields | Display |
|---------|---------------|---------|
| `ParseFailure` | `reason: String` | `"token parse failure: {reason}"` |
| `SignatureInvalid` | `reason: String` | `"token signature invalid: {reason}"` |
| `Expired` | `token_id: String` | `"token expired: {token_id}"` |
| `Revoked` | `token_id: String` | `"token revoked: {token_id}"` |
| `Malformed` | `reason: String` | `"token malformed: {reason}"` |

**Derives**: `Debug`, `thiserror::Error`. Uses `#[error("...")]` for Display.

### EvaluationError

Errors from policy evaluation operations.

| Variant | Context Fields | Display |
|---------|---------------|---------|
| `PolicyLoadFailure` | `reason: String` | `"policy load failure: {reason}"` |
| `ContextBuildFailure` | `reason: String` | `"context build failure: {reason}"` |
| `InternalError` | `reason: String` | `"evaluation internal error: {reason}"` |

**Derives**: `Debug`, `thiserror::Error`. Uses `#[error("...")]` for Display.

---

## Decision and DenyReason (Story 003)

### Decision

| Variant | Payload | Description |
|---------|---------|-------------|
| `Allow` | — | Request passes all checks. Proceed with execution. |
| `Deny` | `reason: DenyReason` | Request denied. Return error to agent with reason code. |
| `Abort` | `reason: String` | Critical failure. Kill the session/execution immediately. |

**Derives**: `Debug`, `Clone`, `PartialEq`, `Serialize`, `Deserialize`

### DenyReason

11 active variants (2 deferred):

| Variant | Display | Notes |
|---------|---------|-------|
| `TokenInvalid` | `"token invalid"` | Signature check failed or unrecognized format |
| `TokenExpired` | `"token expired"` | TTL elapsed |
| `TokenRevoked` | `"token revoked"` | Explicit revocation |
| `PolicyDenied` | `"policy denied"` | Cedar evaluation returned deny |
| `ScopeViolation` | `"scope violation"` | Action/resource outside token scope |
| `ToolNotInScope` | `"tool not in scope"` | Specific tool not in allowed set |
| `MalformedRequest` | `"malformed request"` | Envelope failed validation |
| `AuthorityUnavailable` | `"authority unavailable"` | Cannot reach Authority for token validation |
| `PolicyBundleStale` | `"policy bundle stale"` | Bundle TTL exceeded, no fresh bundle available |
| `CredentialInjectionFailed` | `"credential injection failed"` | Sidecar failed to inject credentials for Stage 3 |
| `ConnectorTimeout` | `"connector timeout"` | Outbound connector timed out |

**Deferred** (documented in code comments):
- `BudgetExceeded` — add when budget tracking mechanism exists
- `RiskThreshold` — add when anomaly detection exists

**Derives**: `Debug`, `Clone`, `PartialEq`, `Eq`, `Serialize`, `Deserialize`
**Display**: Implemented via `thiserror` or manual `Display` impl — human-readable, grep-friendly.

---

## Ubiquitous Language

| Term | Definition |
|------|------------|
| **Capability Token** | A signed, scoped, time-bound credential issued by the Authority to an agent. Contains `CapabilityClaims`. |
| **Execution Envelope** | The protocol unit wrapping every outbound agent call. Contains intent, capability, and metadata. |
| **Execution Context** | Flattened attribute set derived from the envelope, consumed by policy evaluation. |
| **Decision** | The outcome of policy evaluation: Allow, Deny, or Abort. |
| **DenyReason** | Typed reason code explaining why a request was denied. |
| **Stage 1** | Token verification stage in the enforcement pipeline (Sidecar). |
| **Stage 2** | Policy evaluation stage in the enforcement pipeline (Sidecar). |
| **Stage 3** | Credential injection and outbound execution stage (Sidecar). |
| **Policy Bundle** | The set of Cedar policies currently loaded and cached by the Sidecar. |
| **Revocation** | The act of invalidating a token before its natural expiry. |
| **Authority** | The component that issues capability tokens and manages policy bundles. |
| **Sidecar** | The proxy component that intercepts agent calls and enforces policy. |

---

## Story Coverage Matrix

| Story | Entities/Types Covered | Status |
|-------|----------------------|--------|
| 001-capability-token-types | `CapabilityClaims`, `TokenState` | Covered |
| 002-execution-types | `ExecutionEnvelope`, `ExecutionIntent`, `HttpParams`, `DbQueryParams`, `ToolUseParams`, `RequestMetadata`, `ExecutionContext` | Covered |
| 003-decision-and-errors | `Decision`, `DenyReason`, `TokenError`, `EvaluationError` | Covered |
| 004-trait-interfaces | `TokenSigner`, `TokenVerifier`, `PolicyEvaluator`, `PolicyBundleStore`, `RevocationStore`, `PolicyBundle` | Covered |
