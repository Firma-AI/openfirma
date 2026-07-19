---
name: review-rust-code
description: Review Rust changes for correctness, robustness, documentation quality, and test coverage.
---

# Rust Review

Review Rust code changes for correctness, robustness, documentation quality, and test coverage.

## Arguments

Exactly one of the following forms:

- `<revset>`: review a jj revset when the repo uses Jujutsu
- `<commit>` or `<commit1>..<commit2>`: review git commit diff
- `pr:<number>`: review a GitHub pull request locally
- `<path>` or `<path1> <path2>`: review one or more Rust files or directories
- no argument: review uncommitted working tree changes

## Instructions

### 1. Collect the code to review

Use the repository's active VCS as described in `AGENTS.md`.

#### Working-tree review

If no argument was provided, review uncommitted Rust changes:

```bash
# Git
git diff -- '*.rs'

# jj
jj diff --git -- glob:'**/*.rs'
```

#### Revision review

If the input is a Git commit or commit range:

```bash
git show <commit> -- '*.rs'
git diff <commit1>..<commit2> -- '*.rs'
```

If the input is a jj revset:

```bash
jj diff -r <revset> --git -- glob:'**/*.rs'
```

#### PR review

Fetch the PR head locally, then diff it against the default remote branch.

```bash
# Git
git fetch origin refs/pull/<number>/head
git diff origin/main...FETCH_HEAD -- '*.rs'

# jj
git fetch origin refs/pull/<number>/head
pr_sha=$(git rev-parse FETCH_HEAD)
jj git import
jj diff -r "main@origin..$pr_sha" --git -- glob:'**/*.rs'
```

Use Git for fetching `refs/pull/<number>/head`; it is the simplest way to
materialize GitHub PR refs in a jj-backed clone before `jj git import`.

#### Path review

For path-based review, read the full source of all `.rs` files in scope.

Always read full files for anything added or modified, not just diff hunks.

### 2. Review checklist

For each issue, record the file, line, explanation, and suggested fix.

#### 2a. Error handling and repo lint rules

Check for violations of repo constraints:

- `.unwrap()`
- `.expect()`
- `panic!()`
- `unsafe`

Prefer explicit error propagation with `Result<T, E>` and `thiserror`.

#### 2b. Boundary handling and robustness

Look for:

- unchecked indexing
- unchecked conversions or lossy assumptions
- stale or ambiguous config behavior
- surprising defaults in operator-facing code
- platform-specific code that adds fallback, no-op, passthrough, stub, or
  `compile_error!` implementations outside the supported Unix and Windows
  targets

#### 2c. Documentation and tests

Confirm that:

- non-obvious contracts and invariants are documented
- changed behavior has matching tests
- docs are updated when the change affects architecture, CLI, configuration, or user-visible behavior
- `docs-site/public/llms.txt` is updated when discovery or integration guidance changed

Ensure the new code adheres to the policies defined in [`rust-tests-guidelines`](../rust-tests-guidelines/SKILL.md) and [`rust-docs-guidelines`](../rust-docs-guidelines/SKILL.md).

### 3. Emit the report

Report only actionable findings.

Prioritize:

- bugs and regressions
- security weaknesses
- missing tests for changed behavior
- documentation gaps that would mislead contributors or users

If there are no findings, say so plainly and note any residual risk or untested areas.
