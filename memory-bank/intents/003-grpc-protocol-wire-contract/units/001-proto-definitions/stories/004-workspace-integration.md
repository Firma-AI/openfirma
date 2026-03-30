---
story: 004-workspace-integration
unit: 001-proto-definitions
intent: 003-grpc-protocol-wire-contract
priority: must
status: complete
created: 2026-03-27T09:00:00.000Z
---

# Story: Workspace Integration and CI Validation

## Description

Ensure the updated `firma-proto` crate integrates cleanly with the existing workspace and passes all CI checks.

## Acceptance Criteria

- [x] `cargo build --workspace` succeeds
- [x] `cargo clippy --workspace -- -D warnings` passes
- [x] `cargo fmt --check` passes
- [x] `cargo test --workspace` passes
- [x] `make check` passes
- [x] Generated types are importable from `firma_proto` by downstream crates

## Technical Notes

- May need to adjust workspace-level clippy allows for generated code
- Verify `firma-sidecar` and `firma-authority` can add `use firma_proto::*` without issues
