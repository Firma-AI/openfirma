---
name: writing-black-box-tests
description: Writes and verifies OpenFirma CLI, structural-sandbox, live-agent, and VS Code black-box tests. Use when adding or changing user-facing end-to-end coverage.
---

# Writing Black-Box Tests

Exercise OpenFirma through the same compiled CLI boundary its users invoke, and
collect evidence that proves the behavior under test.

## Choose the suite

Choose by the production boundary the test proves, not by whether it starts a
process.

| Suite                 | Current location                  | Use it for                                                            |
| --------------------- | --------------------------------- | --------------------------------------------------------------------- |
| `firma::cli`          | `crates/firma/tests/integration/` | CLI and component contracts, including structural-sandbox regressions |
| `firma::e2e`          | `tests/cli-e2e/`                  | Deterministic full-stack tests through real Authority and Sidecar     |
| `firma::live-agent`   | `tests/e2e/`                      | Claude and Codex behavior that requires a real agent and credentials  |
| `firma::vscode`       | `tests/vscode/`                   | Managed VS Code launch behavior                                       |
| `firma::architecture` | `tests/architecture/`             | Repository structure and dependency invariants                        |

The Cargo target name is authoritative. Some source directory names predate
these boundaries and will be migrated separately.

Use a crate integration suite instead when the behavior is a Rust API contract
rather than user-facing CLI behavior.

Within `firma::cli`:

- parsing, diagnostics, generated files, and one-component lifecycle tests get
  a module named after the command or component;
- tests that run real commands inside a structural sandbox belong in
  `structural_sandbox.rs`;
- policy and pipeline changes should have structural-sandbox coverage whenever
  the behavior is reachable through `firma run`.

FIR-366 remains an ignored regression in `structural_sandbox.rs` because it
documents a structural sandbox weakness. Keep known-failing regression targets
in the module that owns the behavior, but do not count ignored tests as passing
coverage.

Use `firma::live-agent` only when the claim depends on an actual agent's
behavior. Live-agent coverage complements deterministic CLI coverage; it does
not replace it.

## Black-box contract

Every black-box CLI test must:

1. launch `env!("CARGO_BIN_EXE_firma")`, never `firma` from `PATH`;
2. avoid deriving expected values from the production implementation under
   test;
3. assert the exit status and the user-visible output or side effect that proves
   the claim.

Tests that read or write configuration or state must use temporary paths rather
than host defaults. Tests that start services or sandboxed commands must also
use an isolated workspace and bound readiness and process completion instead of
sleeping indefinitely.

For an enforcement allow or deny, process failure alone is not proof. Assert:

- **stimulus:** the sandboxed command actually attempted the operation;
- **effect:** the controlled destination did or did not observe it;
- **decision:** the audit event has the expected action, resource, decision,
  and stable reason category.

Use a unique value in the requested resource to correlate those observations.
For a deny, include a positive control that proves the destination and stimulus
work when the fact under test is removed. Use fresh state for the control and
enforcement runs.

Test doubles narrow the claim. A fake Sidecar or governance endpoint can prove
a client or wire-protocol contract, but the test must remain component-scoped;
it does not prove the full Authority, Sidecar, policy, and dispatch path.

## Workflow

1. State the user-visible claim and the production stage that owns it.
2. Inspect the nearest existing test in the chosen suite.
3. List which production components must be real and any intentional test
   doubles.
4. Identify the stimulus, externally observable effect, and decision evidence.
5. Add the smallest test that closes the gap.
6. Run the narrowest selector with `--no-tests=fail`.
7. Run the containing deterministic suite when the environment supports it.
8. Report what ran and which components, if any, were substituted.

## Commands

Run deterministic CLI tests selected for a normal development host:

```sh
cargo nextest run -p firma --test cli --no-tests=fail
```

Run the active Linux structural-sandbox tests, which the default profile
excludes:

```sh
cargo nextest run --profile ci -p firma --test cli --no-tests=fail \
  -E 'test(/^structural_sandbox::/)'
```

Run the deterministic full-stack suite (excluded by the default profile):

```sh
cargo nextest run --profile ci -p firma --test e2e --no-tests=fail
```

Run the ignored FIR-366 regression explicitly. It is expected to fail until the
weakness is fixed:

```sh
cargo nextest run --profile ci -p firma --test cli --run-ignored all \
  --no-tests=fail \
  -E 'test(=structural_sandbox::child_process_escapes_run_governance)'
```

Run the live-agent suite:

```sh
just live-agent-e2e
```

Run the deterministic managed VS Code launcher test:

```sh
cargo nextest run -p firma --test vscode --run-ignored all \
  --no-tests=fail \
  -E 'test(=fake_vscode_receives_managed_launch_contract_through_firma_run)'
```

For one test, use `-E 'test(=<fully-qualified-test-name>)'` and
`--no-tests=fail`. Module-wide regular expressions are intentionally broader.
