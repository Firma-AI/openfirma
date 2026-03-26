---
id: 001-workspace-setup
unit: 001-workspace-setup
intent: 001-project-scaffolding
type: simple-construction-bolt
status: in-progress
stories:
  - 001-workspace-and-crates
  - 002-clippy-and-fmt
  - 003-ci-pipeline
  - 004-makefile
created: 2026-03-26T10:15:00Z
started: 2026-03-26T10:30:00Z
completed: null
current_stage: plan
stages_completed: []

requires_bolts: []
enables_bolts: []
requires_units: []
blocks: false

complexity:
  avg_complexity: 1
  avg_uncertainty: 1
  max_dependencies: 1
  testing_scope: 1
---

# Bolt: 001-workspace-setup

## Overview

Single bolt covering the entire project scaffolding — Cargo workspace with 4 crates, Clippy config, CI pipeline, and Makefile. Low complexity, no domain logic.

## Objective

Deliver a compiling Cargo workspace where all 4 crates are wired, CI runs on push, and `make check` mirrors CI locally. The team of 3 can start building real components immediately after.

## Stories Included

- **001-workspace-and-crates**: Cargo workspace, 4 crates, dependency graph, stub entrypoints (Must)
- **002-clippy-and-fmt**: Workspace-level Clippy lints and formatting config (Must)
- **003-ci-pipeline**: GitHub Actions workflow for fmt/clippy/test/build (Must)
- **004-makefile**: Makefile with targets mirroring CI (Must)

## Bolt Type

**Type**: Simple Construction Bolt
**Definition**: `.specsmd/aidlc/templates/construction/bolt-types/simple-construction-bolt.md`

## Stages

- [ ] **1. Plan**: Define workspace layout and crate structure
- [ ] **2. Implement**: Create all files — Cargo.toml, stubs, CI workflow, Makefile
- [ ] **3. Test**: Verify `cargo build`, `cargo test`, `cargo clippy`, `cargo fmt`, `make check` all pass

## Dependencies

### Requires

- None (first bolt in the project)

### Enables

- All bolts in intents 002-007

## Success Criteria

- [ ] `cargo build --workspace` succeeds
- [ ] `cargo test --workspace` passes
- [ ] `cargo clippy --workspace -- -D warnings` passes
- [ ] `cargo fmt --check` passes
- [ ] Both binaries start, log, and exit cleanly
- [ ] CI workflow passes on push
- [ ] `make check` runs all checks and passes

## Notes

All 4 stories are in one bolt because they're tightly coupled — workspace structure must exist before linting, CI, or Makefile can work. Simple construction bolt since there's no domain modeling.
