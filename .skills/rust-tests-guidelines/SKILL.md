---
name: rust-tests-guidelines
description: Guidelines for writing Rust tests in OpenFirma.
---

# Rust Test Guidelines

Guidelines for writing new tests for Rust code.

## Guidelines

1. Test through the public API whenever practical.
2. Exercise private behavior through public APIs. If an important branch is
   unreachable that way, ask before changing visibility or adding a test-only
   API.
3. Add edge-case coverage for parsing, validation, and error-handling paths.
4. Use `proptest` where property-based coverage adds real value for invariants or parser-like behavior.
5. Write tests with the same care as production code: clear structure, minimal duplication, readable intent.
6. Avoid comments that depend on exact line numbers.
7. Prefer one test per distinct branch or behavior, not many tests with different inputs that exercise the same control flow.
8. Do not add tests that differ only in input values when they exercise the same branch structure.
9. Do not write standalone tests for trivial delegations or constructors that are already covered transitively unless they encode meaningful validation logic.

## Error assertions

Test an error's structure and its user-visible rendering when both are part of
the contract. Prefer the following assertion strategy at each boundary:

1. For typed domain errors, use `assert_matches!` to verify the variant and any
   meaningful fields, then use an inline `insta::assert_snapshot!` on
   `error.to_string()` when the message is user-visible.
2. For Serde boundaries, verify the error category and meaningful location
   information structurally. Snapshot the OpenFirma-owned source message when
   it can be isolated. Snapshot the complete rendered wrapper only when its
   third-party formatting is intentionally part of the public interface.
3. For `anyhow` errors, downcast and verify the typed source. Snapshot
   `format!("{error:#}")` only when the complete error chain is what a user
   sees; `error.to_string()` may contain only an outer context message.
4. For CLI boundaries, assert the exit status, snapshot the captured `stderr`
   with only narrowly scoped redactions of nondeterministic values, and retain
   separate assertions for important ordering or side-effect invariants.
5. For structured protocol responses and internal state-machine enums, prefer
   exact field or enum assertions. Do not add snapshots when the structured
   value already expresses the complete contract.
6. For third-party errors, cryptographic failures, and intentionally opaque
   implementation details, assert the behavior or classification rather than
   adopting external wording as an OpenFirma snapshot contract.

Avoid bare `.is_err()`, `matches!(error, Variant { .. })`, and
`message.contains(...)` when a stable variant, meaningful fields, or the full
user-visible message can be asserted. Substring checks remain useful as
supplementary assertions for ordering and absence guarantees.

When adding an error variant or changing a user-visible error message, inspect
the affected tests for both structural coverage and rendered-message coverage.

## Snapshot hygiene

1. Prefer inline snapshots so reviewers can see the expected diagnostic beside
   the assertion.
2. Redact only exact nondeterministic values, such as temporary paths,
   timestamps, ports, and generated identifiers. Assert that each original
   value is present before replacing it, and preserve all surrounding text and
   ordering.
3. Keep exact fixture values only when those values are behaviorally meaningful.
4. Review snapshot changes rather than accepting them blindly.
5. Do not leave `.snap.new` or `.pending-snap` artifacts in the working copy.

## Code organization

1. Put all new Rust tests in crate-level `tests/` integration suites.
2. Do not add `#[cfg(test)]` modules or inline tests to `src/` files.
3. Do not change visibility or add test-only APIs solely to enable integration tests without explicit approval.
4. Add doctests only when the example is genuinely useful documentation, not just another place to duplicate unit coverage.
