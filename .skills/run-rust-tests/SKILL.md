---
name: run-rust-tests
description: Run Rust tests for the affected OpenFirma crates or a specific crate/test.
---

# Run Rust Tests

Run Rust tests after making changes to verify correctness.

## Arguments

- No arguments: determine affected crates and run their tests
- `all`: run all Rust tests in the workspace
- `<crate>`: run tests for one crate
- `<crate> <test>`: run one test in one crate

Arguments provided: `$ARGUMENTS`

## Instructions

### No arguments

1. Inspect the modified files using the repository's active VCS as described in `AGENTS.md`.

```bash
# Git
git status --short
git diff --name-only

# jj
jj status
jj diff --name-only
```

2. Identify changed workspace crates from paths under `crates/<name>/`.
3. Run nextest for those crates:

```bash
cargo nextest run -p <crate1> -p <crate2>
```

4. Run doctests for the same crates when they may be affected:

```bash
cargo test --doc -p <crate1> -p <crate2>
```

5. If no affected crates can be determined, run all Rust tests.

### `all`

```bash
just test
```

### One crate

```bash
cargo nextest run -p <crate-name>
cargo test --doc -p <crate-name>
```

### One crate, one test

```bash
cargo nextest run -p <crate-name> <test-name>
```

### Firma black-box suites

Load and follow
[`writing-black-box-tests`](../writing-black-box-tests/SKILL.md) for the
current CLI, deterministic E2E, live-agent, and VS Code commands.

If the target is a doctest-specific failure, use:

```bash
cargo test --doc -p <crate-name>
```

## Notes

- `cargo nextest` does not run doctests in this repo.
- Prefer targeted crate runs while iterating, then `just test` or `just check` at the end.
