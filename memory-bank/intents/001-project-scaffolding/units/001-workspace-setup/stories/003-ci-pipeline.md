---
id: 003-ci-pipeline
unit: 001-workspace-setup
intent: 001-project-scaffolding
status: draft
priority: must
created: 2026-03-26T10:15:00Z
assigned_bolt: null
implemented: false
---

# Story: 003-ci-pipeline

## User Story

**As a** developer on the Firma OSS team
**I want** a GitHub Actions CI pipeline that runs on every push and PR
**So that** regressions are caught before code reaches main

## Acceptance Criteria

- [ ] **Given** a push to any branch or a PR opened, **When** CI triggers, **Then** it runs: `cargo fmt --check`, `cargo clippy --workspace -- -D warnings`, `cargo test --workspace`, `cargo build --workspace`
- [ ] **Given** the scaffolded codebase, **When** CI runs, **Then** all checks pass
- [ ] **Given** a PR with a Clippy violation, **When** CI runs, **Then** the PR is blocked by a failing check

## Technical Notes

- Single workflow file at `.github/workflows/ci.yml`
- Use `actions/checkout` and `dtolnay/rust-toolchain` with stable Rust
- Cache cargo registry and target dir for speed
- Run steps sequentially: fmt → clippy → test → build (fail fast)

## Dependencies

### Requires

- 001-workspace-and-crates (needs something to build)
- 002-clippy-and-fmt (CI runs these checks)

### Enables

- None directly — CI is the safety net

## Edge Cases

| Scenario | Expected Behavior |
|----------|-------------------|
| CI cache miss | Full build from scratch, slower but still passes |
| Rust toolchain update | Pinned in workflow, updated explicitly |

## Out of Scope

- Release builds or artifact publishing
- Matrix builds across multiple OS/arch
- Code coverage reporting
