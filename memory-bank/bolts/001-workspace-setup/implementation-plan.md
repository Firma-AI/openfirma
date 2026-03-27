---
stage: plan
bolt: 001-workspace-setup
created: 2026-03-26T10:30:00Z
---

## Implementation Plan: workspace-setup

### Objective

Create a compiling Cargo workspace with 4 crates, strict Clippy lints, a GitHub Actions CI pipeline, and a Makefile for local checks. Minimal stubs — no business logic, no real interfaces.

### Deliverables

- Root `Cargo.toml` workspace definition with 4 members
- `crates/firma-core/` — library crate, stub `lib.rs`
- `crates/firma-proto/` — library crate, stub `lib.rs` (no prost/tonic)
- `crates/firma-sidecar/` — binary crate, stub `main.rs` with tokio + tracing
- `crates/firma-authority/` — binary crate, stub `main.rs` with tokio + tracing
- Workspace-level Clippy lint configuration
- `.github/workflows/ci.yml` — CI pipeline
- `Makefile` — local check targets mirroring CI

### Dependencies

- `tokio` (runtime for binary crates): async runtime
- `tracing` + `tracing-subscriber` (logging for binary crates): structured logging
- No other external dependencies at this stage

### Technical Approach

**Workspace layout**:

```
Cargo.toml                          # workspace root
Makefile
.github/workflows/ci.yml
crates/
├── firma-core/
│   ├── Cargo.toml
│   └── src/lib.rs
├── firma-proto/
│   ├── Cargo.toml
│   └── src/lib.rs
├── firma-sidecar/
│   ├── Cargo.toml
│   └── src/main.rs
└── firma-authority/
    ├── Cargo.toml
    └── src/main.rs
```

**Dependency graph**:

```
firma-core (no workspace deps)
    ↑
firma-proto (depends on firma-core)
    ↑
firma-sidecar (depends on firma-core + firma-proto)
firma-authority (depends on firma-core + firma-proto)
```

**Clippy config** in root `Cargo.toml` via `[workspace.lints.clippy]`:

- `pedantic = "warn"`
- `unwrap_used = "deny"`
- `expect_used = "deny"`
- `panic = "deny"`
- `module_name_repetitions = "allow"`

Plus `[workspace.lints.rust]`: `unsafe_code = "deny"`

Each crate inherits via `[lints] workspace = true`.

**Binary stubs**: `#[tokio::main]` that initializes `tracing_subscriber`, logs startup, exits.

**CI workflow**: Single job with stable Rust, cached deps, sequential steps (fmt → clippy → test → build).

**Makefile targets**: `fmt`, `lint`, `test`, `build`, `check` (runs all in sequence).

### Acceptance Criteria

- [ ] `cargo build --workspace` succeeds
- [ ] `cargo test --workspace` passes
- [ ] `cargo clippy --workspace -- -D warnings` passes
- [ ] `cargo fmt --check` passes
- [ ] `cargo run --bin firma-sidecar` starts, logs, exits with code 0
- [ ] `cargo run --bin firma-authority` starts, logs, exits with code 0
- [ ] `make check` runs all checks and passes
- [ ] CI workflow file exists at `.github/workflows/ci.yml`
