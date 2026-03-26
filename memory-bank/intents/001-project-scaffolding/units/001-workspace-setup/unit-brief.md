---
unit: 001-workspace-setup
intent: 001-project-scaffolding
phase: inception
status: ready
unit_type: backend
default_bolt_type: simple-construction-bolt
created: 2026-03-26T10:15:00Z
updated: 2026-03-26T10:15:00Z
---

# Unit Brief: Workspace Setup

## Purpose

Set up the Cargo workspace with all four crates (`firma-core`, `firma-proto`, `firma-sidecar`, `firma-authority`), configure linting, CI, and a Makefile for local development. Minimal stubs only — no real interfaces or business logic.

## Scope

### In Scope

- Cargo workspace with 4 member crates
- Correct inter-crate dependency graph
- Stub `main.rs` for binaries, stub `lib.rs` for libraries
- Workspace-level Clippy configuration
- GitHub Actions CI workflow
- Makefile with targets mirroring CI

### Out of Scope

- Real trait definitions (intent 002)
- Protobuf/gRPC setup (intent 003)
- Any runtime behavior beyond "start and log"

---

## Assigned Requirements

| FR | Requirement | Priority |
|----|-------------|----------|
| FR-1 | Cargo Workspace Setup | Must |
| FR-2 | Crate Dependency Graph | Must |
| FR-3 | Stub Binary Entrypoints | Must |
| FR-4 | Clippy and Formatting Configuration | Must |
| FR-5 | CI Pipeline | Must |
| FR-6 | Makefile for Local Checks | Must |
| FR-7 | Proto Stub | Must |

---

## Domain Concepts

### Key Entities

| Entity | Description | Attributes |
|--------|-------------|------------|
| Workspace | Root Cargo.toml with member crates | members, resolver |
| Crate | Individual workspace member | name, type (lib/bin), dependencies |

### Key Operations

| Operation | Description | Inputs | Outputs |
|-----------|-------------|--------|---------|
| Build | Compile all crates | Source files | Binaries + libs |
| Check | Run fmt + clippy + test + build | Source files | Pass/fail |

---

## Story Summary

| Metric | Count |
|--------|-------|
| Total Stories | 4 |
| Must Have | 4 |
| Should Have | 0 |
| Could Have | 0 |

### Stories

| Story ID | Title | Priority | Status |
|----------|-------|----------|--------|
| 001-workspace-and-crates | Workspace and crate structure | Must | Planned |
| 002-clippy-and-fmt | Clippy and formatting config | Must | Planned |
| 003-ci-pipeline | GitHub Actions CI | Must | Planned |
| 004-makefile | Makefile for local checks | Must | Planned |

---

## Dependencies

### Depends On

None — this is the foundational intent.

### Depended By

| Unit | Reason |
|------|--------|
| All units in intents 002-007 | Every subsequent intent builds on this workspace |

### External Dependencies

| System | Purpose | Risk |
|--------|---------|------|
| GitHub Actions | CI runner | Low |
| crates.io | Dependency registry | Low |

---

## Constraints

- Rust 2021 edition, stable toolchain
- Binary crates use tokio runtime
- No external service dependencies
- Keep stubs minimal

---

## Success Criteria

### Functional

- [ ] `cargo build --workspace` succeeds
- [ ] `cargo test --workspace` passes
- [ ] `cargo clippy --workspace -- -D warnings` passes
- [ ] `cargo fmt --check` passes
- [ ] Both binaries start, log, and exit
- [ ] CI passes on push
- [ ] `make check` runs all checks

### Quality

- [ ] Crate dependency graph matches system architecture
- [ ] Makefile targets mirror CI exactly

---

## Notes

Simple construction bolt — no domain modeling needed. This is pure project setup.
