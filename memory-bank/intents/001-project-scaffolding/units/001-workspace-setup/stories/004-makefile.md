---
id: 004-makefile
unit: 001-workspace-setup
intent: 001-project-scaffolding
status: complete
priority: must
created: 2026-03-26T10:15:00.000Z
assigned_bolt: null
implemented: true
---

# Story: 004-makefile

## User Story

**As a** developer on the Firma OSS team
**I want** a Makefile that mirrors CI checks locally
**So that** I can run the same checks before pushing without surprises

## Acceptance Criteria

- [ ] **Given** the workspace, **When** I run `make fmt`, **Then** it runs `cargo fmt --check`
- [ ] **Given** the workspace, **When** I run `make lint`, **Then** it runs `cargo clippy --workspace -- -D warnings`
- [ ] **Given** the workspace, **When** I run `make test`, **Then** it runs `cargo test --workspace`
- [ ] **Given** the workspace, **When** I run `make build`, **Then** it runs `cargo build --workspace`
- [ ] **Given** the workspace, **When** I run `make check`, **Then** it runs fmt, lint, test, and build in sequence
- [ ] **Given** all checks pass, **When** I run `make check`, **Then** it exits with code 0

## Technical Notes

- Makefile at workspace root
- `.PHONY` targets for all commands
- `make check` runs all targets in order, fails fast on first error
- Keep it simple — no variable interpolation or conditional logic

## Dependencies

### Requires

- 001-workspace-and-crates (needs crates for cargo commands)
- 002-clippy-and-fmt (make lint runs clippy)

### Enables

- None — developer convenience tool

## Edge Cases

| Scenario | Expected Behavior |
|----------|-------------------|
| Running on system without make | Clear error; make is standard on dev machines |
| Running `make check` with a lint failure | Stops at lint step, reports failure |

## Out of Scope

- Watch mode or incremental rebuilds
- Docker build targets
- Release/publish targets
