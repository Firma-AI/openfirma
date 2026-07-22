---
title: Test policies offline with firma policy
description: Validate Cedar policies against the canonical Firma schema and assert ALLOW/DENY decisions with TOML fixtures, fully local and fail-closed.
---

`firma policy` is the offline policy developer loop. It lets you author a Cedar
policy, schema-check it, write a fixture that pins the expected decision, and
gate both in CI — without an Authority, a Sidecar, or any network access.

Both subcommands are **fully local, deterministic, and fail-closed**. The Cedar
schema is embedded in the binary (`firma_core::cedar::FIRMA_SCHEMA`), so the
verdict you get here is the verdict the Sidecar hot path produces for the
equivalent request. Any I/O, parse, schema, or evaluation error prints a
diagnostic to stderr and exits non-zero — no path silently exits `0`.

## 1. Author a policy

Create a bundle directory and drop a Cedar policy in it. This one permits the
low-risk `code.read` action class:

```cedar
// policies/allow-code-read.cedar
permit(
  principal,
  action == Firma::Action::"code.read",
  resource
);
```

The action `class` must be a real entry in the
[canonical action-class registry](../../concepts/action-classes/). Names like
`model.inference.chat` are **not** in the schema; using one fails closed.

## 2. Validate it

`firma policy validate <file.cedar>` reads the file, parses it as a Cedar
policy set, and strictly type-checks it against the embedded canonical schema.
A valid policy prints `OK` to stdout and exits `0`:

```console
$ firma policy validate policies/allow-code-read.cedar
OK
```

On failure it prints a [miette](https://github.com/zkat/miette) diagnostic with
a `line:col` location and a source caret to stderr, and exits `1`. Here a
policy references an action that does not exist in the schema:

```console
$ firma policy validate bad.cedar
error: policy 'bad.cedar' failed schema validation:
  x validation error on policy `policy0` at offset 33-64: unrecognized action `Firma::Action::"does.not.exist"`
   ,-[3:13]
 2 |   principal,
 3 |   action == Firma::Action::"does.not.exist",
   :             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 4 |   resource
   `----
  help: did you mean `Firma::Action::"code.write"`?
  x validation error on policy `policy0` at offset 0-79: unable to find an applicable action given the policy scope constraints
   ,-[1:1]
 1 | ,-> permit(
 2 | |     principal,
 3 | |     action == Firma::Action::"does.not.exist",
 4 | |     resource
 5 | `-> );
   `----
```

Validation also catches type errors — for example, comparing the `Long`
attribute `context.transfer_amount` against a string is a strict schema error.

## 3. Write a fixture

A fixture is a TOML file describing one authorization request plus the decision
you expect. `firma policy test <fixture.toml>` builds a Cedar request whose
principal, action, resource, and context exactly mirror the Sidecar hot path,
evaluates the bundle, and compares the decision to `expected`:

```toml
# allow-code-read.toml
[fixture]
expected = "ALLOW"

[fixture.principal]
agent_id = "agt_01j0000000e008000000000001"

[fixture.action]
class = "code.read"

[fixture.resource]
host = "api.github.com"

[bundle]
path = "policies"
```

The fixture shape:

| Key                   | Required | Meaning                                           |
| --------------------- | -------- | ------------------------------------------------- |
| `[fixture] expected`  | yes      | `ALLOW` or `DENY`, case-insensitive.              |
| `[fixture.principal]` | yes      | `agent_id` — parsed into a `Firma::Agent` UID.    |
| `[fixture.action]`    | yes      | `class` — a canonical action-class name.          |
| `[fixture.resource]`  | yes      | `host` — becomes the `Firma::Resource` UID.       |
| `[fixture.context]`   | no       | Per-attribute overrides on the canonical context. |
| `[bundle] path`       | yes      | Directory of `*.cedar` files to evaluate against. |

Bundle rules:

- `[bundle] path` reads **every `*.cedar` file directly inside the
  directory**, filename-sorted, **non-recursive** (subdirectories are
  ignored).
- A **relative** `path` resolves against the **fixture file's parent
  directory**, not the current working directory.
- The schema is **always** the embedded canonical schema. Any
  `*.cedarschema` file you place in the bundle directory is ignored.

## 4. Run the test

A matching decision prints the decision line to stdout and exits `0`. The line
is `<DECISION> <reasons>`, where reasons is a comma-joined list of contributing
policy ids (or `-` when none):

```console
$ firma policy test allow-code-read.toml
ALLOW policy0
```

A mismatch still prints the actual decision (so it stays parseable) but adds an
explanation to stderr and exits `1`:

```console
$ firma policy test mismatch.toml
ALLOW policy0
error: decision mismatch: expected DENY, got ALLOW
```

## Context defaults and overrides

This is the most important behavior to understand. The canonical schema
declares **16 required `EnforcementContext` attributes**. You almost never set
all of them — `firma policy test` supplies every one by default, mirroring the
Sidecar's `build_context` on the hot path, so a fixture verdict equals the
enforcement verdict for an equivalent plain request.

The 6 commonly-tuned keys and their defaults:

| Key                  | Default       | Notes                                |
| -------------------- | ------------- | ------------------------------------ |
| `session_id`         | `"fixture"`   | String session identifier.           |
| `timestamp_ms`       | now (Unix ms) | Current time so you need not pin it. |
| `params`             | `"{}"`        | Serialized request params.           |
| `risk_score`         | `0`           | Integer risk score.                  |
| `session_duration_s` | `0`           | Seconds since session start.         |
| `action_count`       | `1`           | Actions taken in the session so far. |

The other 6 default to the sidecar's plain-request placeholders and are
overridable: `transfer_amount`, `daily_cumulative_amount`,
`transfers_last_10m`, `same_payee_count_30m`, `session_transfer_count` all
default to `0`; `raw_transport` defaults to `"https"`.

Override any attribute with a `[fixture.context]` block. This fixture exercises
a payment-cap policy by setting the transfer amount:

```toml
[fixture]
expected = "ALLOW"

[fixture.principal]
agent_id = "agt_01j0000000e008000000000001"

[fixture.action]
class = "payment.transfer"

[fixture.resource]
host = "api.stripe.com"

[fixture.context]
transfer_amount = 500

[bundle]
path = "policies"
```

```console
$ firma policy test payment-ok.toml
ALLOW policy0
```

An **unknown context key** — one not declared on `EnforcementContext` — is
**not** silently dropped. Cedar's schema-strict request build rejects it, and
the command fails closed with exit `1`. The same is true for an action `class`
that is not in the registry:

```console
$ firma policy test bad-action.toml
error: failed to build Cedar context (schema-strict): action `Firma::Action::"model.inference.chat"` does not exist in the supplied schema
```

## Invariants

- **Fully local.** No Authority, no Sidecar, no network. Safe in CI and on a
  laptop.
- **Embedded schema.** Validation and evaluation always use the canonical
  schema compiled into the binary; bundle-local schema files are ignored.
- **Deterministic.** Same policies + same fixture = same decision. Bundle
  files are concatenated in a stable, filename-sorted order.
- **Fail-closed.** Every I/O, parse, schema, or evaluation error becomes a
  stderr diagnostic and a non-zero exit. Nothing silently exits `0`.

## Gate it in CI

Block broken policies before they land with a pre-commit hook:

```bash
#!/usr/bin/env bash
# .git/hooks/pre-commit
set -euo pipefail
for f in $(git diff --cached --name-only --diff-filter=ACM -- '*.cedar'); do
  firma policy validate "$f"
done
```

And run validation plus every fixture as a CI gate:

```yaml
# .github/workflows/policy.yml
- name: Validate Cedar policies
  run: |
    find policies -name '*.cedar' -print0 \
      | xargs -0 -n1 firma policy validate
- name: Run policy fixtures
  run: |
    find tests/fixtures -name '*.toml' -print0 \
      | xargs -0 -n1 firma policy test
```

Because both subcommands exit non-zero on any failure, no extra assertion
scripting is needed — the exit code is the gate.

## What's next

- [Write your first Cedar policy](../write-a-cedar-policy/) — author and reload
  a real runtime policy against a running Sidecar.
- [Action classes](../../concepts/action-classes/) — the canonical registry of
  action-class names you reference in `[fixture.action] class`.
- [Policies](../../concepts/policies/) — how the Sidecar evaluates the same
  Cedar policies on the enforcement hot path.
