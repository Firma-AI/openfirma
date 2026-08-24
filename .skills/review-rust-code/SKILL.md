---
name: review-rust-code
description: Applies Rust-specific correctness, robustness, documentation, and test-coverage checks to a review target already resolved by reviewing-changes.
---

# Rust Review

Apply this specialization after
[`reviewing-changes`](../reviewing-changes/SKILL.md) has established the exact
review target. Use its baseline scope and reporting contract; do not reacquire
or redefine the diff.

Always read full files for anything added or modified, not just diff hunks.

## Review checklist

For each issue, record the file, line, explanation, and suggested fix.

### Error handling and repo lint rules

Check for violations of repo constraints:

- `.unwrap()`
- `.expect()`
- `panic!()`
- `unsafe`

Prefer explicit error propagation with `Result<T, E>` and `thiserror`.

### Boundary handling and robustness

Look for:

- unchecked indexing
- unchecked conversions or lossy assumptions
- stale or ambiguous config behavior
- surprising defaults in operator-facing code
- abstractions or contracts coupled to an incidental backend, transport, or OS
  rather than enduring domain semantics
- local parsers, constants, builders, identifiers, or fixtures that duplicate
  a canonical owner or helper
- platform-specific code that adds fallback, no-op, passthrough, stub, or
  `compile_error!` implementations outside the supported Unix and Windows
  targets

### Domain and type modeling

Where the change affects domain, security, lifecycle, or protocol semantics,
check whether:

- a semantically distinct identity or constrained value remains an unchecked
  raw primitive;
- `Option<T>` conflates genuine absence, invalidity, and lifecycle state;
- a `bool` hides multiple states or legal transitions;
- validation is repeated because no canonical validated type owns it;
- public fields, constructors, or mutation bypass an invariant owner;
- type, method, variant, event, error, configuration, or wire names introduce
  conflicting terms; or
- construction and transition APIs admit illegal states or role combinations.

For a claim that an API makes a state unrepresentable, try compile-valid
constructor witnesses that swap same-typed semantic roles, provide multiple
values from one role or provenance, bypass validation, or take an illegal
transition. Distinguish cardinality and ownership uniqueness from semantic role
identity; named fields do not establish that same-typed constructor arguments
were produced for the correct roles.

Report these only when the state is reachable and causes concrete correctness,
security, compatibility, operational, or recurring-validation impact. Do not
report a preference for a newtype, enum, typestate, rename, or abstraction
without that causal chain.

### Documentation and tests

Confirm that:

- non-obvious contracts and invariants are documented
- changed behavior has matching tests
- docs are updated when the change affects architecture, CLI, configuration, or user-visible behavior
- [`docs-site/public/llms.txt`](../../docs-site/public/llms.txt) is updated when discovery or integration guidance changed

Ensure the new code adheres to the policies defined in [`rust-tests-guidelines`](../rust-tests-guidelines/SKILL.md) and [`rust-docs-guidelines`](../rust-docs-guidelines/SKILL.md).

## Rust-specific reporting requirements

Follow the baseline report and prioritization contract in `reviewing-changes`.

For a type-model or abstraction finding, identify the reachable invalid state,
its owner and consumers, the observable impact, and what the proposed shape
would replace or deliberately leave unsolved.
