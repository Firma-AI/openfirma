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
  - `normalizer` — Maps raw HTTP requests to canonical `ExecutionEnvelope` with normalized `intent.action_class` from a 44-class registry (15 FEP v0.1 + 12 GitHub + 12 Stripe + 5 Gmail additions). `intent.resource` is a `BTreeMap<String, String>` with conventional keys `host`, `path`, and optionally `provider` (attached only when the request host exact-matches a known allowlist: `api.github.com` / `github.com` → `provider="github"`; `api.stripe.com` → `provider="stripe"`; `gmail.googleapis.com` → `provider="gmail"`). Fail-closed: unclassifiable protected actions → DENY.
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

## Mapping rules configuration

The normalizer's host/method/path → action_class mapping is loaded from TOML at
startup by `startup::pipeline::build_pipeline_runtime`. Two config knobs on
`[enforcement.mapping]` (see `crates/firma-sidecar/src/config/enforcement.rs`):

- `rules_path: String` — primary mapping file (defaults to `mapping-rules.toml`).
- `rules_paths: Vec<String>` — additional mapping files merged on top.

Rules from `rules_path` and each entry of `rules_paths` are concatenated and
passed to `MappingTable::from_config`. Duplicate `(method, host, path)` tuples
across merged files fail at startup (fail-closed).

Shipped mapping files live under `crates/firma-sidecar/config/mappings/`:

| File          | Covers                                                        |
|---------------|---------------------------------------------------------------|
| `github.toml` | 44 GitHub REST endpoints → 12 action classes                  |
| `stripe.toml` | 88 Stripe REST endpoints → 14 action classes                  |
| `gmail.toml`  | 41 Gmail REST endpoints → 7 action classes                    |

Example operator config:

```toml
[enforcement.mapping]
rules_path = "config/mappings/default.toml"
rules_paths = [
  "crates/firma-sidecar/config/mappings/github.toml",
  "crates/firma-sidecar/config/mappings/stripe.toml",
  "crates/firma-sidecar/config/mappings/gmail.toml",
]
```

See `docs/markdown/firma_action_class_registry.md` for the full 44-class
registry and `intent.resource` shape conventions.

## Documentation

After any major behavior, architecture, CLI, configuration, or public API change,
update the docs site under `docs-site/` in the same change set. Write docs for
human readers first: concise, concrete, task-oriented, and clear about examples,
operational gotchas, and relevant invariants.

## TOML Formatting

Always run `taplo format` after modifying any `.toml` file.

## Linting Rules

Workspace lints are strict — these are enforced in CI:

- `clippy::pedantic` warn, `clippy::unwrap_used` deny, `clippy::expect_used` deny, `clippy::panic` deny
- `unsafe_code` deny

This means: no `.unwrap()`, no `.expect()`, no `panic!()`, no `unsafe`. Use `Result<T, E>` with `thiserror` for all error handling.
