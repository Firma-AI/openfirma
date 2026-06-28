# AGENTS.md

Guidance for coding agents working in this repository.

## Key Commands

```bash
just check # Run all local verification checks (CI parity)
just fmt # dprint check (TOML + Markdown + Rust)
just lint # cargo clippy --workspace -- -D warnings
just test # cargo nextest run + cargo test --doc
just build # cargo build --workspace
```

Tests run via `cargo nextest` (process-per-test isolation); doctests run
separately via `cargo test --doc` since nextest does not run them.

Requires `protoc` installed for `firma-proto` protobuf compilation.

## Formatting

`dprint` is the single formatter for the repo. Run `dprint fmt` after modifying
`.toml`, `.md`, or `.rs` files. `just fmt` runs `dprint check` in CI.

`docs-site/` is excluded and uses its own toolchain.

## Linting Rules

Workspace lints are strict and enforced in CI:

- `clippy::pedantic` warn
- `clippy::unwrap_used` deny
- `clippy::expect_used` deny
- `clippy::panic` deny
- `unsafe_code` deny

Do not use `.unwrap()`, `.expect()`, `panic!()`, or `unsafe`. Prefer
`Result<T, E>` with `thiserror` for error handling.

## Supported Platforms

OpenFirma supports only Unix and Windows targets. When implementing
platform-specific behavior, use `#[cfg(unix)]` and `#[cfg(windows)]` code paths.
Do not add fallback, no-op, passthrough, stub, or `compile_error!` code for
unsupported targets. It is acceptable for unsupported targets to fail naturally
due to missing platform-specific implementations.

## Version Control

Some contributors use Git, some use Jujutsu.

- Invoke `jj` from the working copy to determine whether the local clone uses
  Jujutsu; do not infer this by inspecting the filesystem for `.jj/`.
- If the `jj` probe succeeds, prefer `jj` commands for history, diff, conflict
  resolution, and changeset manipulation.
- If the `jj` probe fails because the clone is not a Jujutsu workspace, use Git.
- Do not assume every clone uses `jj`; detect the active VCS before choosing
  commands.
- When giving user-facing revision identifiers or instructions, match the VCS
  actually in use in that clone.

## Atomic Revisions

Whenever the working copy is already dirty or you are about to touch revision
history, use the repository skills instead of improvising:

- [`commit-guidelines`](.skills/commit-guidelines/SKILL.md) for dirty-worktree
  inspection, atomic checkpoint commits/changesets, and reviewed-history
  preservation
- [`split-jj-changeset`](.skills/split-jj-changeset/SKILL.md) for splitting
  mixed Jujutsu changesets
- [`verify`](.skills/verify/SKILL.md) for per-revision and final verification

Use commits or jj changesets as local checkpoints during substantial work.
Prefer small atomic revisions that can stand on their own when feasible.

## Architecture

OpenFirma is an L7 policy enforcement sidecar for AI agents. Every outbound
agent call passes through the Sidecar before reaching external systems.

### Crates

- `firma-core` — shared types and trait contracts such as `Decision`,
  `ExecutionEnvelope`, `CapabilityClaims`, `TokenVerifier`, `TokenSigner`,
  `PolicyEvaluator`, and `RevocationStore`. No dependencies on other crates.
- `firma-proto` — gRPC wire contract via protobuf. `build.rs` compiles `.proto`
  files with `tonic-build`.
- `firma-sidecar` — enforcement proxy binary. Key top-level modules:
  - `interceptor` — captures outbound agent traffic.
  - `normalizer` — maps raw HTTP requests to canonical `ExecutionEnvelope`
    values with normalized action classes. Unclassifiable protected actions
    fail closed to DENY.
  - `enforcement` — two-stage engine: capability validation, then constraint
    enforcement.
  - `pipeline` — orchestrates normalizer and enforcement through a single
    `enforce()` entry point.
- `firma-authority` — local/dev Authority reference implementation. Issues
  PASETO v4 tokens and streams policy bundles and revocations. Never on the hot
  path.

### Key Invariants

- Fail closed: every error becomes a DENY decision.
- No network on the hot path: enforcement is fully local.
- Deterministic enforcement: same context plus same policy bundle yields the
  same decision.
- Immutable execution envelopes: treat `ExecutionEnvelope` as immutable once
  created.

## Mapping Rules Configuration

The normalizer's host/method/path to action-class mapping is loaded from TOML
at startup by `startup::pipeline::build_pipeline_runtime`.

`[enforcement.mapping]` supports:

- `rules_path: String` — primary mapping file, defaulting to
  `mapping-rules.toml`.
- `rules_paths: Vec<String>` — additional mapping files merged on top.

Rules from `rules_path` and each entry in `rules_paths` are concatenated before
passing to `MappingTable::from_config`. Duplicate `(method, host, path)` tuples
across merged files fail at startup.

Shipped mapping files live under `crates/firma-sidecar/config/mappings/`:

- `github.toml`
- `stripe.toml`
- `gmail.toml`

## Documentation

After any major behavior, architecture, CLI, configuration, or public API change,
update the docs site under `docs-site/` in the same change set. If the change
affects how people should discover or integrate OpenFirma, update
`docs-site/public/llms.txt` as well.

Write docs for a human reader first:

- Start from the user's task or question, not from internal implementation order.
- Keep prose concise, concrete, and free of marketing filler.
- Prefer small examples, commands, and links to related pages over long theory.
- Name important invariants explicitly: fail closed, no network on the hot path,
  deterministic enforcement, and immutable execution envelopes.
- Document sharp edges and operational gotchas when they affect real use.
