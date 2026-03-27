---
story: 003-build-pipeline
unit: 001-proto-definitions
intent: 003-grpc-protocol-wire-contract
priority: must
status: planned
created: 2026-03-27T09:00:00.000Z
---

# Story: prost/tonic Build Pipeline

## Description

Set up the `build.rs` and `Cargo.toml` configuration to compile `.proto` files into Rust code via tonic-build.

## Acceptance Criteria

- [ ] `build.rs` compiles both `authority.proto` and `types.proto`
- [ ] `Cargo.toml` has prost and tonic as dependencies, tonic-build as build-dependency
- [ ] `lib.rs` re-exports generated code via `tonic::include_proto!`
- [ ] Generated code passes clippy (with appropriate allows for generated code)
- [ ] No `firma-core` dependency in `firma-proto` (dependency goes the other way)

## Technical Notes

- Use `tonic_build::configure().compile_protos()` in `build.rs`
- Proto files located at `proto/firma/v1/`
- Generated code output to default `OUT_DIR`
