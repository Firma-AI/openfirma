# Coding Standards

## Overview

Idiomatic Rust standards optimized for a security-critical sidecar proxy. Strict linting with no panics in production paths, structured async-aware logging, and property-based testing for policy/token edge cases.

## Code Formatting

**Tool**: rustfmt (default configuration)

Rust community standard. No custom overrides — consistency across the ecosystem matters more than personal preference.

**Enforcement**: Pre-commit hook + CI check (`cargo fmt --check`)

## Linting

**Tool**: Clippy
**Strictness**: Pedantic with security-focused deny list

**Key Rules**:

- `#![warn(clippy::pedantic)]` — Catch subtle bugs, enforce idiomatic patterns
- `#![deny(clippy::unwrap_used)]` — No `.unwrap()` in library/production code (panics kill the sidecar, taking down agent networking)
- `#![deny(clippy::expect_used)]` — Same rationale; use `?` operator or explicit error handling
- `#![deny(clippy::panic)]` — No explicit panics in production paths
- `#![warn(clippy::nursery)]` — Opt-in to newer lints for early bug detection
- `#![deny(unsafe_code)]` — No unsafe blocks unless explicitly justified and audited
- Allow `clippy::module_name_repetitions` — Common in domain-driven Rust code

**Exceptions**: `unwrap()` and `expect()` are allowed in test code (`#[cfg(test)]`).

**Enforcement**: CI runs `cargo clippy -- -D warnings`

## Naming Conventions

Standard Rust conventions (enforced by compiler and Clippy):

| Element | Convention | Example |
|---------|------------|---------|
| Variables | snake_case | `token_id`, `is_expired` |
| Functions | snake_case | `validate_token`, `evaluate_policy` |
| Structs | PascalCase | `ExecutionEnvelope`, `CapabilityToken` |
| Enums | PascalCase | `EnforcementDecision` |
| Enum variants | PascalCase | `Allow`, `Deny`, `Abort` |
| Traits | PascalCase | `PolicyEvaluator`, `TokenValidator` |
| Constants | UPPER_SNAKE_CASE | `MAX_TOKEN_TTL`, `DEFAULT_BUNDLE_REFRESH` |
| Modules | snake_case | `capability_token`, `cedar_eval` |
| Type parameters | Single uppercase or PascalCase | `T`, `E`, `ConnectorType` |
| Crate names | kebab-case | `firma-sidecar`, `firma-authority` |

**File Naming**: snake_case, matching module name (e.g., `execution_envelope.rs`)

**Boolean naming**: `is_`, `has_`, `can_` prefixes (e.g., `is_revoked`, `has_expired`, `can_retry`)

## File Organization

**Pattern**: Domain-driven with Rust workspace

**Conventions**:

- Each domain concept gets its own module directory
- `mod.rs` avoided in favor of `module_name.rs` + `module_name/` (Rust 2018+ style)
- Integration tests in `tests/` directory per crate
- Unit tests co-located in source files (`#[cfg(test)] mod tests`)
- Shared types and logic in `firma-core` crate
- Protobuf definitions isolated in `firma-proto` crate

## Testing Strategy

**Test Runner**: cargo-nextest (faster parallel execution, better output)
**Property Testing**: proptest (for token validation, policy evaluation edge cases)

**Test Types**:

| Type | Location | When to Use |
|------|----------|-------------|
| Unit | `#[cfg(test)] mod tests` in source file | Pure functions, type conversions, error cases |
| Integration | `crates/*/tests/` | Cross-module behavior, proxy pipeline, gRPC flows |
| Property-based | Alongside unit or integration tests | Token parsing, Cedar policy edge cases, envelope validation |
| End-to-end | `tests/e2e/` at workspace root | Full proxy flow: agent → sidecar → target |

**Coverage Target**: Critical paths must be tested (enforcement pipeline, token validation, policy eval). No hard percentage — focus on security-critical paths over coverage numbers.

**Conventions**:

- Test naming: `fn test_{function}_{scenario}_{expected}()` (e.g., `test_validate_token_expired_returns_deny`)
- Test structure: Arrange-Act-Assert
- Mock strategy: Minimal mocks. Use real Cedar policy evaluation. Mock only external boundaries (network, clock).
- Test data: Builder pattern for complex types (e.g., `ExecutionEnvelopeBuilder::new().with_intent("http_get").build()`)
- `#[tokio::test]` for async tests

## Error Handling

**Pattern**: `thiserror` for typed domain errors, `anyhow` only in binary entrypoints

**Domain Error Enums** (in `firma-core`):

```rust
#[derive(Debug, thiserror::Error)]
pub enum EnforcementError {
    #[error("token validation failed: {reason}")]
    TokenInvalid { reason: String },

    #[error("token revoked: {token_id}")]
    TokenRevoked { token_id: String },

    #[error("policy denied: {action} on {resource}")]
    PolicyDenied { action: String, resource: String },

    #[error("budget exceeded: {remaining} remaining")]
    BudgetExceeded { remaining: f64 },
}
```

**Rules**:

- Every crate defines its own error enum with `thiserror`
- Use `?` operator for propagation — never `.unwrap()` or `.expect()` in production
- Map errors at crate boundaries (don't leak internal error types)
- Include structured context in errors (token_id, action, resource) for audit trail
- Binary entrypoints (`main.rs`) may use `anyhow::Result` for convenience

## Logging

**Tool**: `tracing` with `tracing-subscriber`
**Format**: JSON in production, pretty-print in development

**Levels**:

| Level | Usage |
|-------|-------|
| ERROR | Enforcement failures, system errors, policy bundle refresh failures |
| WARN | Token nearing expiry, policy bundle TTL approaching, degraded state |
| INFO | Session creation, enforcement decisions (ALLOW/DENY/ABORT), policy bundle updates |
| DEBUG | Execution Envelope details, Cedar evaluation context, connector dispatch |
| TRACE | Raw HTTP request/response bodies, full token claims (dev only) |

**Structured Spans**:

- Per-session span: `session_id`, `agent_id`
- Per-request span: `request_id`, `intent`, `target`
- Per-enforcement span: `stage`, `decision`, `latency_us`

**Rules**:

- Always log: enforcement decisions, session lifecycle, policy bundle changes, errors
- Never log: capability token contents, injected credentials, API keys, raw secrets
- Redact: agent request bodies beyond what's needed for audit (configurable)
- Include `request_id` correlation in all spans for distributed tracing
