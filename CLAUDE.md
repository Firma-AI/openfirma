# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
make check          # Run fmt + lint + test + build (CI parity)
make fmt            # cargo fmt --check
make lint           # cargo clippy --workspace -- -D warnings
make test           # cargo test --workspace
make build          # cargo build --workspace
```

Single crate: `cargo test -p firma-sidecar`
Single test: `cargo test -p firma-sidecar pipeline::tests::test_enforce_happy_path`

Requires `protoc` installed for `firma-proto` protobuf compilation.

## Architecture

L7 policy enforcement sidecar for AI agents. Every outbound agent call passes through the Sidecar before reaching external systems.

### Crates

- **firma-core** — Shared types and trait contracts (`Decision`, `ExecutionEnvelope`, `CapabilityClaims`, `TokenVerifier`, `TokenSigner`, `PolicyEvaluator`, `RevocationStore`). No dependencies on other crates.
- **firma-proto** — gRPC wire contract via protobuf. `build.rs` compiles `.proto` files with `tonic-build`. Generated code has relaxed clippy lints.
- **firma-sidecar** — The enforcement proxy binary. Four top-level modules:
  - `interceptor` — Captures outbound agent traffic (placeholder).
  - `normalizer` — Maps raw HTTP requests to canonical `ExecutionEnvelope` with normalized `intent.action_class` from a 15-class registry. Fail-closed: unclassifiable protected actions → DENY.
  - `enforcement` — Two-stage engine, both fully local with no network calls:
    - Stage 1 (`capability_validation`): Token selection from `CapabilityMap`, then parse/verify/expiry/revocation. Target < 1ms p95.
    - Stage 2 (`constraint_enforcement`): Scope check, bundle freshness, Cedar policy eval. Target < 200µs p95.
  - `pipeline` — Orchestrates normalizer → Stage 1 → Stage 2. Single `enforce()` entry point. Re-exports all public API types; `enforcement` and `normalizer` are `pub(crate)`.
- **firma-authority** — Mini Authority reference implementation for local dev. Issues PASETO v4 tokens, streams policy bundles and revocations. Pre-flight only, never on the hot path.

### Key Invariants

- **Fail-closed**: Every error becomes a DENY decision. No error path silently allows.
- **No network on hot path**: Stage 1 and Stage 2 are fully local. Authority is contacted only at pre-flight (capability issuance).
- **Deterministic enforcement**: Same context + same policy bundle = same decision. No probabilistic classifiers on the hot path.
- **ExecutionEnvelope immutability**: Treated as immutable once created. Enrichment (e.g., credential injection) produces derived structures.

## Linting Rules

Workspace lints are strict — these are enforced in CI:

- `clippy::pedantic` warn, `clippy::unwrap_used` deny, `clippy::expect_used` deny, `clippy::panic` deny
- `unsafe_code` deny

This means: no `.unwrap()`, no `.expect()`, no `panic!()`, no `unsafe`. Use `Result<T, E>` with `thiserror` for all error handling.
