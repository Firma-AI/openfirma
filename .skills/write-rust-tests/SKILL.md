---
name: write-rust-tests
description: Write Rust tests for OpenFirma crates while avoiding redundant coverage.
---

# Write Rust Tests

Write new Rust tests for OpenFirma code.

## Arguments

- `<path>`: path to a crate or Rust file
- `<path1> <path2>`: multiple crate or file paths

## Instructions

1. Identify the public behavior, branch, or invariant that needs coverage.
2. For CLI, deterministic E2E, live-agent, or VS Code coverage, load and follow
   [`writing-black-box-tests`](../writing-black-box-tests/SKILL.md) before
   choosing a file.
3. Otherwise, place the test in the owning crate's integration suite.
4. Check existing tests before writing anything new.
5. Add the smallest test set that covers the missing behavior.
6. Run the relevant tests.
7. Follow [`rust-tests-guidelines`](../rust-tests-guidelines/SKILL.md) for test quality and organization rules.

## What to test

- success and failure paths
- boundary conditions
- configuration parsing and validation
- documentation examples when they are intended to be runnable

## Validation

After adding tests, run the smallest relevant test command first. Use
[`run-rust-tests`](../run-rust-tests/SKILL.md) for command selection.
