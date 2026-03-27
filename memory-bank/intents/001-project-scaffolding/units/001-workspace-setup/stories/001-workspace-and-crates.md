---
id: 001-workspace-and-crates
unit: 001-workspace-setup
intent: 001-project-scaffolding
status: complete
priority: must
created: 2026-03-26T10:15:00.000Z
assigned_bolt: null
implemented: true
---

# Story: 001-workspace-and-crates

## User Story

**As a** developer on the Firma OSS team
**I want** a Cargo workspace with all four crates correctly wired
**So that** I can start building components in the right crate from day one

## Acceptance Criteria

- [ ] **Given** the repo is cloned, **When** I run `cargo build --workspace`, **Then** all 4 crates compile successfully
- [ ] **Given** the workspace exists, **When** I inspect `Cargo.toml`, **Then** it lists `firma-core`, `firma-proto`, `firma-sidecar`, `firma-authority` as members
- [ ] **Given** `firma-sidecar` and `firma-authority` are binary crates, **When** I run `cargo run --bin firma-sidecar` or `cargo run --bin firma-authority`, **Then** each starts a tokio runtime, logs a startup message, and exits cleanly
- [ ] **Given** `firma-core` and `firma-proto` are library crates, **When** I inspect their `Cargo.toml`, **Then** they have `[lib]` sections
- [ ] **Given** the dependency graph, **When** I check `firma-core`, **Then** it has no workspace dependencies
- [ ] **Given** the dependency graph, **When** I check `firma-proto`, **Then** it depends on `firma-core` only
- [ ] **Given** the dependency graph, **When** I check `firma-sidecar` and `firma-authority`, **Then** each depends on `firma-core` and `firma-proto`

## Technical Notes

- Root `Cargo.toml` uses `resolver = "2"`
- Crates live under `crates/` directory (e.g., `crates/firma-core/`)
- Binary crates use `#[tokio::main]` with `tracing` for the startup log
- `firma-proto` is a pure stub `lib.rs` with no prost/tonic deps yet
- Rust 2021 edition

## Dependencies

### Requires

- None (first story)

### Enables

- 002-clippy-and-fmt (needs crates to exist for linting)
- 003-ci-pipeline (needs crates to build)
- 004-makefile (needs crates for targets)

## Edge Cases

| Scenario | Expected Behavior |
|----------|-------------------|
| Running binary with no args | Logs startup message and exits with code 0 |
| Building on stable Rust | Compiles without nightly features |

## Out of Scope

- Real trait definitions or business logic
- Protobuf build pipeline
- Any runtime behavior beyond startup log
