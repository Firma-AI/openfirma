---
intent: 001-project-scaffolding
phase: inception
status: inception-complete
created: 2026-03-26T10:00:00Z
updated: 2026-03-26T10:15:00Z
---

# Requirements: Project Scaffolding

## Intent Overview

Set up the Cargo workspace with all four crates (`firma-core`, `firma-proto`, `firma-sidecar`, `firma-authority`), establish crate boundaries and dependency graph, configure CI, and provide a Makefile for local checks. Keep stubs minimal — this is the foundation for a team of 3 to start building on.

## Business Goals

| Goal | Success Metric | Priority |
|------|----------------|----------|
| All 4 crates compile and link | `cargo build --workspace` succeeds | Must |
| CI pipeline catches regressions from day one | CI runs fmt, clippy, test, build on every push | Must |
| Crate boundaries match architecture | Dependency graph enforces no circular deps, sidecar/authority depend on core+proto | Must |
| Local check parity with CI | `make check` runs same checks as CI | Must |

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

### FR-4: Clippy and Formatting Configuration

- **Description**: Configure workspace-level Clippy lints per coding standards (`pedantic`, `deny(unwrap_used)`, `deny(expect_used)`, `deny(panic)`, `deny(unsafe_code)`)
- **Acceptance Criteria**: `cargo clippy --workspace -- -D warnings` passes; `cargo fmt --check` passes
- **Priority**: Must

### FR-5: CI Pipeline

- **Description**: GitHub Actions workflow that runs `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test --workspace`, and `cargo build --workspace` on push and PR
- **Acceptance Criteria**: CI runs on push to main and on PRs; all checks pass on the scaffolded codebase
- **Priority**: Must

### FR-6: Makefile for Local Checks

- **Description**: A Makefile at workspace root with targets mirroring CI: `make fmt`, `make lint`, `make test`, `make build`, and a `make check` that runs all of them in sequence
- **Acceptance Criteria**: `make check` runs all checks locally and passes; targets match what CI runs
- **Priority**: Must

### FR-7: Proto Stub

- **Description**: `firma-proto` crate with a minimal `lib.rs` stub. No `prost`/`tonic` build deps, no Protobuf files. Real proto setup deferred to intent 003.
- **Acceptance Criteria**: Crate compiles as part of workspace; no external build dependencies beyond what's in `firma-core`
- **Priority**: Must

---

## Non-Functional Requirements

None for this intent. Build performance and code quality standards are covered by project-wide standards.

---

## Constraints

### Technical Constraints

**Project-wide standards**: Coding standards, tech stack, and system architecture from `memory-bank/standards/` apply.

**Intent-specific constraints**:

- Workspace must use Rust 2021 edition
- Binary crates use `tokio` runtime with `#[tokio::main]`
- No external service dependencies — scaffolding must compile and test offline
- Keep stubs minimal — avoid over-engineering interfaces that will be designed in intent 002/003

### Business Constraints

- Team of 3 developers will be working from this foundation
- Correctness of crate boundaries is more important than feature completeness

---

## Assumptions

| Assumption | Risk if Invalid | Mitigation |
|------------|-----------------|------------|
| Four-crate split matches final architecture | Refactoring crate boundaries later is expensive | Validated against system-architecture.md and component reference |
| Rust stable toolchain is sufficient | Nightly features would complicate CI | Avoid nightly-only features |
