---
id: 002-clippy-and-fmt
unit: 001-workspace-setup
intent: 001-project-scaffolding
status: draft
priority: must
created: 2026-03-26T10:15:00Z
assigned_bolt: null
implemented: false
---

# Story: 002-clippy-and-fmt

## User Story

**As a** developer on the Firma OSS team
**I want** strict Clippy lints and formatting enforced across the workspace
**So that** code quality is consistent from the first commit

## Acceptance Criteria

- [ ] **Given** the workspace, **When** I run `cargo fmt --check`, **Then** it passes with no formatting issues
- [ ] **Given** the workspace, **When** I run `cargo clippy --workspace -- -D warnings`, **Then** it passes with no warnings
- [ ] **Given** workspace-level lint config, **When** I check the root `Cargo.toml` or crate configs, **Then** `clippy::pedantic` is warned, and `clippy::unwrap_used`, `clippy::expect_used`, `clippy::panic`, `unsafe_code` are denied
- [ ] **Given** a crate's `lib.rs` or `main.rs`, **When** I add `.unwrap()` to production code, **Then** Clippy fails the build

## Technical Notes

- Lint configuration via `[workspace.lints.clippy]` in root `Cargo.toml` (Rust 1.74+)
- Each crate inherits workspace lints via `[lints] workspace = true`
- Allow `clippy::module_name_repetitions` per coding standards

## Dependencies

### Requires

- 001-workspace-and-crates (crates must exist)

### Enables

- 003-ci-pipeline (CI runs these checks)
- 004-makefile (make lint runs clippy)

## Edge Cases

| Scenario | Expected Behavior |
|----------|-------------------|
| `.unwrap()` in `#[cfg(test)]` code | Allowed — test code is exempt |
| New crate added without inheriting lints | Will not compile if workspace lint policy uses `deny` |

## Out of Scope

- Custom Clippy configuration beyond coding standards
- Pre-commit hooks (could be added later)
