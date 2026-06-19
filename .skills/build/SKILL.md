---
name: build
description: Compile OpenFirma to verify changes build successfully. Use this after code changes and before running broader verification.
---

# Build Skill

Compile OpenFirma to verify changes build successfully.

## Usage

Run this skill after making code changes to ensure the workspace still compiles.

## Instructions

### Full workspace build

```bash
make build
```

### Single-crate build

For focused iteration on one crate:

```bash
cargo build -p <crate-name> --all-features
```

Examples:

```bash
cargo build -p firma-sidecar --all-features
cargo build -p firma-run --all-features
```

### If build fails

- Read the compiler errors carefully.
- If protobuf-related code fails, confirm `protoc` is installed.
- If the failure is in generated gRPC code, check the corresponding `.proto` and `build.rs` inputs.
- Fix the issue and re-run the build.

## Notes

- `make check` already includes `make build`, so a full PR validation does not need a separate build step.
- Prefer `make build` over ad hoc cargo invocations unless you are intentionally narrowing scope.
