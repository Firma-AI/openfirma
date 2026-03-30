---
unit: 001-types-and-traits
bolt: 002-types-and-traits
stage: design
status: complete
updated: 2026-03-28T10:15:00Z
---

# Technical Design — Types and Traits

## Architecture Pattern

**Flat module library** — no layered architecture needed. `firma-core` is a pure-types library crate with no I/O, no runtime behavior, and no framework. Each domain concept gets its own module file. Public API is surfaced via `lib.rs` re-exports.

Rationale: The traditional DDD layered architecture (presentation → application → domain → infrastructure) does not apply here. There is no persistence, no API surface, no use cases — only type definitions, trait contracts, and error types. A flat module layout keeps the crate simple and navigable.

---

## Module Structure

```text
crates/firma-core/
├── Cargo.toml
└── src/
    ├── lib.rs          # Module declarations, public re-exports
    ├── token.rs        # CapabilityClaims, TokenState
    ├── envelope.rs     # ExecutionEnvelope, ExecutionIntent, HttpParams,
    │                   # DbQueryParams, ToolUseParams, RequestMetadata,
    │                   # ExecutionContext
    ├── decision.rs     # Decision, DenyReason
    ├── error.rs        # TokenError, EvaluationError
    └── traits.rs       # TokenSigner, TokenVerifier, PolicyEvaluator,
                        # PolicyBundleStore, RevocationStore, PolicyBundle
```

### Module Responsibilities

| Module | Types | Story |
|--------|-------|-------|
| `token` | `CapabilityClaims`, `TokenState` | 001 |
| `envelope` | `ExecutionEnvelope`, `ExecutionIntent`, `HttpParams`, `DbQueryParams`, `ToolUseParams`, `RequestMetadata`, `ExecutionContext` | 002 |
| `decision` | `Decision`, `DenyReason` | 003 |
| `error` | `TokenError`, `EvaluationError` | 003 |
| `traits` | `TokenSigner`, `TokenVerifier`, `PolicyEvaluator`, `PolicyBundleStore`, `RevocationStore`, `PolicyBundle` | 004 |

### Design Rationale: Separate `decision.rs` and `error.rs`

`Decision`/`DenyReason` are domain outcomes — they represent what the system decided. `TokenError`/`EvaluationError` are operational failures — they represent what went wrong. Different consumers care about different types: the enforcement pipeline uses `Decision`, while error handling and `Result` types use the errors. Separating them avoids a monolithic "types" file and keeps imports focused.

---

## Public API Surface (`lib.rs`)

`lib.rs` declares all modules and re-exports every public type at the crate root. Downstream crates use `firma_core::CapabilityClaims`, not `firma_core::token::CapabilityClaims`.

### Re-export Strategy

```text
// Module declarations
mod token;
mod envelope;
mod decision;
mod error;
mod traits;

// Re-export everything public
pub use token::{CapabilityClaims, TokenState};
pub use envelope::{
    ExecutionEnvelope, ExecutionIntent, HttpParams, DbQueryParams,
    ToolUseParams, RequestMetadata, ExecutionContext,
};
pub use decision::{Decision, DenyReason};
pub use error::{TokenError, EvaluationError};
pub use traits::{
    TokenSigner, TokenVerifier, PolicyEvaluator,
    PolicyBundleStore, RevocationStore, PolicyBundle,
};
```

**Rationale**: Flat re-exports at crate root are idiomatic for Rust library crates with a moderate number of types (~20). Downstream users get clean `use firma_core::X` imports. Module paths remain available for disambiguation if needed.

---

## Dependencies

### New Dependencies for `firma-core/Cargo.toml`

| Crate | Version | Features | Purpose |
|-------|---------|----------|---------|
| `serde` | workspace | `derive` | `Serialize`/`Deserialize` derives for all types |
| `serde_json` | workspace | — | `serde_json::Value` for `ToolUseParams::input` |
| `thiserror` | workspace | — | `Error`/`Display` derives for error enums |
| `chrono` | workspace | `serde` | `DateTime<Utc>` for timestamps, serde integration |

### Workspace-Level Dependency Additions

These must be added to `[workspace.dependencies]` in the root `Cargo.toml`:

| Crate | Version | Features |
|-------|---------|----------|
| `serde` | `1` | `derive` |
| `serde_json` | `1` | — |
| `thiserror` | `2` | — |
| `chrono` | `0.4` | `serde` |

### firma-core `Cargo.toml` Changes

Dependencies reference the workspace versions:

```toml
[dependencies]
serde = { workspace = true }
serde_json = { workspace = true }
thiserror = { workspace = true }
chrono = { workspace = true }
```

### No New Dependencies

- No `cedar-policy` (constraint)
- No `rusty_paseto` (that's Unit 002 / bolt 003)
- No async runtime (pure sync types)
- No `std::collections::HashMap` needs import (it's in `std` prelude — used for `HttpParams::headers`)

---

## Type Design Details

### token.rs

```text
CapabilityClaims
├── token_id: String
├── agent_id: String
├── session_id: String
├── actions: Vec<String>
├── resources: Vec<String>
├── issued_at: DateTime<Utc>
├── expires_at: DateTime<Utc>
└── context_hash: String

Derives: Debug, Clone, PartialEq, Serialize, Deserialize

TokenState
├── Issued
├── Active
├── InUse
├── Expired
├── Revoked
└── Aborted

Derives: Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize
```

**Notes**:
- `TokenState` gets `Copy` — it's a fieldless enum, cheap to copy.
- No `Default` on `CapabilityClaims` — all fields are mandatory, no sensible defaults.

### envelope.rs

```text
ExecutionEnvelope
├── intent: ExecutionIntent
├── capability: String
└── metadata: RequestMetadata

ExecutionIntent (enum)
├── Http(HttpParams)
├── DbQuery(DbQueryParams)
└── ToolUse(ToolUseParams)

HttpParams
├── method: String
├── url: String
└── headers: HashMap<String, String>

DbQueryParams
├── statement: String
├── db_name: String
└── read_only: bool

ToolUseParams
├── tool_name: String
└── input: serde_json::Value

RequestMetadata
├── session_id: String
├── agent_id: String
├── timestamp: DateTime<Utc>
└── trace_id: Option<String>

ExecutionContext
├── agent_id: String
├── action: String
├── resource: String
├── session_id: String
├── token_id: String
├── token_actions: Vec<String>
└── token_resources: Vec<String>

All derive: Debug, Clone, Serialize, Deserialize
```

**Notes**:
- `HashMap` import: `use std::collections::HashMap;` at top of `envelope.rs`.
- `ExecutionContext` does NOT implement `From<...>` in this unit — the conversion logic requires Sidecar-specific derivation (mapping intent variants to action/resource strings). A builder or constructor will be added in intent 006. For now, `ExecutionContext` is constructible via struct literal.

### decision.rs

```text
Decision (enum)
├── Allow
├── Deny { reason: DenyReason }
└── Abort { reason: String }

Derives: Debug, Clone, PartialEq, Serialize, Deserialize

DenyReason (enum)
├── TokenInvalid
├── TokenExpired
├── TokenRevoked
├── PolicyDenied
├── ScopeViolation
├── ToolNotInScope
├── MalformedRequest
├── AuthorityUnavailable
├── PolicyBundleStale
├── CredentialInjectionFailed
└── ConnectorTimeout

Derives: Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize
```

**Notes**:
- `DenyReason` gets `Copy` — fieldless enum.
- `Display` for `DenyReason` implemented via `thiserror` `#[error("...")]` on each variant — produces lowercase, hyphen-free, grep-friendly strings.
- `Decision` gets `PartialEq` (not `Eq`) because `Abort { reason: String }` contains `String` which is `Eq` — actually both are fine. Use `PartialEq` since `Deny` contains `DenyReason` which is `Eq`, and `Abort` has `String` which is also `Eq`. So `Decision` can derive `Eq` too.
- Correction: `Decision` derives `PartialEq, Eq` — all variant payloads are `Eq`.

### error.rs

```text
TokenError (enum, thiserror)
├── ParseFailure { reason: String }     → "token parse failure: {reason}"
├── SignatureInvalid { reason: String }  → "token signature invalid: {reason}"
├── Expired { token_id: String }        → "token expired: {token_id}"
├── Revoked { token_id: String }        → "token revoked: {token_id}"
└── Malformed { reason: String }        → "token malformed: {reason}"

EvaluationError (enum, thiserror)
├── PolicyLoadFailure { reason: String }    → "policy load failure: {reason}"
├── ContextBuildFailure { reason: String }  → "context build failure: {reason}"
└── InternalError { reason: String }        → "evaluation internal error: {reason}"

Both derive: Debug, thiserror::Error
```

**Notes**:
- Error types intentionally do NOT derive `Clone` — errors are propagated once via `?`, not copied.
- Error types do NOT derive `Serialize` — they are operational, not domain data. Audit logging converts them to strings via `Display`.

### traits.rs

```text
PolicyBundle — opaque newtype: pub struct PolicyBundle { _private: () }
  - Derives: Debug, Clone
  - Private field prevents external construction — must come from PolicyBundleStore
  - Internals added in later intents when Cedar integration is built

TokenSigner (trait)
  fn sign(&self, claims: &CapabilityClaims) -> Result<String, TokenError>

TokenVerifier (trait)
  fn verify(&self, raw_token: &str) -> Result<CapabilityClaims, TokenError>

PolicyEvaluator (trait)
  fn evaluate(&self, context: &ExecutionContext) -> Result<Decision, EvaluationError>

PolicyBundleStore (trait)
  fn load_bundle(&self) -> Result<PolicyBundle, EvaluationError>
  fn get_version(&self) -> Option<String>
  fn is_fresh(&self) -> bool

RevocationStore (trait)
  fn is_revoked(&self, token_id: &str) -> Result<bool, TokenError>
  fn add_revocation(&self, token_id: &str) -> Result<(), TokenError>
```

**Object Safety**: All traits are object-safe:
- No associated types
- No generic methods
- No `Self` in return position
- No `Sized` bound (implicitly `?Sized` for trait objects)
- All method signatures use `&self` receiver

**Send + Sync**: Not explicitly bounded on the traits. Implementations that need to be shared across Tokio tasks will add `Send + Sync` at the usage site (e.g., `Arc<dyn TokenVerifier + Send + Sync>`). This keeps the core traits simple.

---

## Security Design

| Concern | Approach |
|---------|----------|
| No unsafe code | `#![deny(unsafe_code)]` workspace lint inherited |
| No unwrap/expect | `#![deny(clippy::unwrap_used)]` and `#![deny(clippy::expect_used)]` inherited |
| No secret data in Display | Error `Display` impls show token_id and reason strings, never token contents or keys |
| Injection prevention | `ExecutionIntent` uses typed enum variants, not generic maps |
| Type-level scope enforcement | `CapabilityClaims` carries explicit `actions` and `resources` — scope checks use these |

---

## NFR Implementation

| Requirement | Design Approach |
|-------------|-----------------|
| NFR-2: No unsafe code | Workspace lint `deny(unsafe_code)` — applies automatically |
| NFR-3: No network I/O | No async runtime, no network crates in dependencies. Pure computation. |
| API stability | Flat re-exports from `lib.rs`. Adding types is backward-compatible. Removing/changing fields is breaking. |
| Clippy pedantic | Workspace lint config inherited. `module_name_repetitions` allowed. |

NFR-1 (performance) applies to bolt 003 (PASETO v4), not this bolt.

---

## Cross-Module Dependencies (Internal)

```text
token.rs ──(no deps)──
envelope.rs ──(no deps)──
decision.rs ──(no deps)──
error.rs ──(no deps)──
traits.rs ──depends on──> token.rs (CapabilityClaims)
traits.rs ──depends on──> envelope.rs (ExecutionContext)
traits.rs ──depends on──> decision.rs (Decision)
traits.rs ──depends on──> error.rs (TokenError, EvaluationError)
```

`traits.rs` is the only module with internal dependencies. All other modules are self-contained. This means the implementation order is:
1. `token.rs`, `envelope.rs`, `decision.rs`, `error.rs` (any order, no cross-deps)
2. `traits.rs` (after all others)
3. `lib.rs` (re-exports, after all modules exist)

---

## Test Strategy (Preview)

Tests will be co-located in each module (`#[cfg(test)] mod tests`):

| Module | Test Focus |
|--------|-----------|
| `token` | CapabilityClaims construction, serde round-trip, TokenState exhaustive match |
| `envelope` | ExecutionEnvelope construction, ExecutionIntent variant construction, serde round-trip |
| `decision` | Decision construction, DenyReason Display output, serde round-trip |
| `error` | TokenError Display output, EvaluationError Display output |
| `traits` | Object-safety verification (`Box<dyn Trait>` compiles), mock impl compiles |

Full test details in Stage 5.
