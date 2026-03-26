---
stage: implement
bolt: 001-workspace-setup
created: 2026-03-26T10:40:00Z
---

## Implementation Walkthrough: workspace-setup

### Summary

Created a Cargo workspace with 4 crates, workspace-level Clippy lint configuration, a GitHub Actions CI workflow, and a Makefile for local checks. All checks pass.

### Structure Overview

Root workspace with crates under `crates/` directory. Two library crates (`firma-core`, `firma-proto`) and two binary crates (`firma-sidecar`, `firma-authority`). Dependencies flow upward: core has none, proto depends on core, both binaries depend on core + proto.

### Completed Work

- [x] `Cargo.toml` - Workspace root with 4 members, resolver 2, shared dependencies, lint config
- [x] `crates/firma-core/Cargo.toml` - Library crate, no workspace deps
- [x] `crates/firma-core/src/lib.rs` - Stub library
- [x] `crates/firma-proto/Cargo.toml` - Library crate, depends on firma-core
- [x] `crates/firma-proto/src/lib.rs` - Stub library, re-exports firma_core
- [x] `crates/firma-sidecar/Cargo.toml` - Binary crate, depends on firma-core + firma-proto
- [x] `crates/firma-sidecar/src/main.rs` - Tokio runtime + tracing startup log
- [x] `crates/firma-authority/Cargo.toml` - Binary crate, depends on firma-core + firma-proto
- [x] `crates/firma-authority/src/main.rs` - Tokio runtime + tracing startup log
- [x] `.github/workflows/ci.yml` - CI pipeline: fmt, clippy, test, build
- [x] `Makefile` - Local check targets mirroring CI

### Key Decisions

- **Clippy pedantic priority**: Set `pedantic = { level = "warn", priority = -1 }` so individual lint overrides take precedence over the group. Required by `clippy::lint_groups_priority`.
- **Workspace dependencies**: `tokio`, `tracing`, `tracing-subscriber` defined at workspace level for version consistency.
- **Workspace package metadata**: `edition`, `license`, `repository` shared via `[workspace.package]`.

### Deviations from Plan

None.

### Dependencies Added

- [x] `tokio` v1 (rt-multi-thread, macros) - async runtime for binary crates
- [x] `tracing` v0.1 - structured logging
- [x] `tracing-subscriber` v0.3 (env-filter, json) - log formatting and filtering

### Developer Notes

- `firma-proto` re-exports `firma_core` to avoid unused dependency warnings
- Binary stubs use `unwrap_or_else` for env filter (not `.unwrap()`) to satisfy the deny lint
