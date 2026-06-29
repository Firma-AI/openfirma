---
name: rust-tests-guidelines
description: Guidelines for writing Rust tests in OpenFirma.
---

# Rust Test Guidelines

Guidelines for writing new tests for Rust code.

## Guidelines

1. Test through the public API whenever practical.
2. Test private APIs only when the important logic cannot be exercised cleanly through public behavior.
3. Add edge-case coverage for parsing, validation, and error-handling paths.
4. Use `proptest` where property-based coverage adds real value for invariants or parser-like behavior.
5. Write tests with the same care as production code: clear structure, minimal duplication, readable intent.
6. Avoid comments that depend on exact line numbers.
7. Prefer one test per distinct branch or behavior, not many tests with different inputs that exercise the same control flow.
8. Do not add tests that differ only in input values when they exercise the same branch structure.
9. Do not write standalone tests for trivial delegations or constructors that are already covered transitively unless they encode meaningful validation logic.

## Code organization

1. Put all new Rust tests in crate-level `tests/` integration suites.
2. Do not add `#[cfg(test)]` modules or inline tests to `src/` files.
3. If behavior is only reachable through private helpers, prefer testing it through public behavior. If that is impractical, ask before changing visibility or adding test-only APIs.
4. Add doctests only when the example is genuinely useful documentation, not just another place to duplicate unit coverage.
