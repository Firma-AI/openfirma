---
intent: 001-project-scaffolding
phase: inception
status: draft
created: 2026-03-26T10:00:00Z
updated: 2026-03-26T10:00:00Z
---

# Requirements: Project Scaffolding

## Intent Overview

Set up the Cargo workspace with all four crates (`firma-core`, `firma-proto`, `firma-sidecar`, `firma-authority`), establish crate boundaries and dependency graph, configure CI, and provide stub implementations with key trait definitions and mock impls. This gives every subsequent intent a working project structure to build on.

## Business Goals

| Goal | Success Metric | Priority |
|------|----------------|----------|
| All 4 crates compile and link | `cargo build --workspace` succeeds | Must |
| CI pipeline catches regressions from day one | CI runs fmt, clippy, test, build on every push | Must |
| Crate boundaries match architecture | Dependency graph enforces no circular deps, sidecar/authority depend on core+proto | Must |
| Key traits defined for downstream mocking | Storage traits (`PolicyStore`, `AuditSink`, `RevocationStore`, `CredentialStore`) exist with mock impls | Should |

---

## Functional Requirements

### FR-1: Cargo Workspace Setup

- **Description**: Create a Cargo workspace with four member crates: `firma-core` (library), `firma-proto` (library), `firma-sidecar` (binary), `firma-authority` (binary)
- **Acceptance Criteria**: `cargo build --workspace` compiles successfully; `cargo test --workspace` runs with no failures
- **Priority**: Must

### FR-2: Crate Dependency Graph

- **Description**: Establish correct inter-crate dependencies: `firma-sidecar` depends on `firma-core` + `firma-proto`; `firma-authority` depends on `firma-core` + `firma-proto`; `firma-proto` depends on `firma-core`; `firma-core` has no internal workspace deps
- **Acceptance Criteria**: Dependency graph matches system architecture; no circular dependencies
- **Priority**: Must

### FR-3: Stub Binary Entrypoints

- **Description**: `firma-sidecar` and `firma-authority` each have a `main.rs` that starts a minimal tokio runtime and logs a startup message
- **Acceptance Criteria**: `cargo run --bin firma-sidecar` and `cargo run --bin firma-authority` both start and exit cleanly
- **Priority**: Must

### FR-4: Core Trait Definitions

- **Description**: Define key storage/abstraction traits in `firma-core`: `PolicyStore`, `AuditSink`, `RevocationStore`, `CredentialStore` with minimal method signatures
- **Acceptance Criteria**: Traits compile; each has at least one mock/stub implementation in a `mock` module
- **Priority**: Should

### FR-5: Clippy and Formatting Configuration

- **Description**: Configure workspace-level Clippy lints per coding standards (`pedantic`, `deny(unwrap_used)`, `deny(expect_used)`, `deny(panic)`, `deny(unsafe_code)`)
- **Acceptance Criteria**: `cargo clippy --workspace -- -D warnings` passes; `cargo fmt --check` passes
- **Priority**: Must

### FR-6: CI Pipeline

- **Description**: GitHub Actions workflow that runs `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test --workspace`, and `cargo build --workspace` on push and PR
- **Acceptance Criteria**: CI runs on push to main and on PRs; all checks pass on the scaffolded codebase
- **Priority**: Must

### FR-7: Proto Stub

- **Description**: `firma-proto` crate with placeholder module structure ready for Protobuf definitions in intent 003
- **Acceptance Criteria**: Crate compiles; has a stub module that re-exports placeholder types
- **Priority**: Should

---

## Non-Functional Requirements

### Build Performance

| Requirement | Metric | Target |
|-------------|--------|--------|
| Clean build time | Wall clock | < 60s on CI |
| Incremental build | Wall clock | < 10s locally |

---

## Constraints

### Technical Constraints

**Project-wide standards**: Coding standards, tech stack, and system architecture from `memory-bank/standards/` apply.

**Intent-specific constraints**:

- Workspace must use latest Rust
- Binary crates use `tokio` runtime with `#[tokio::main]`
- No external service dependencies — scaffolding must compile and test offline

### Business Constraints

- This is the foundation for all subsequent intents — correctness of crate boundaries is more important than feature completeness

---

## Assumptions

| Assumption | Risk if Invalid | Mitigation |
|------------|-----------------|------------|
| Four-crate split matches final architecture | Refactoring crate boundaries later is expensive | Validated against system-architecture.md and component reference |
| Rust stable toolchain is sufficient | Nightly features would complicate CI | Avoid nightly-only features |

---

## Open Questions

| Question | Owner | Due Date | Resolution |
|----------|-------|----------|------------|
| Should `firma-proto` include prost/tonic build deps now or defer to intent 003? | Team | Before construction | Pending |
| Should workspace include a `tests/e2e/` directory stub? | Team | Before construction | Pending |
