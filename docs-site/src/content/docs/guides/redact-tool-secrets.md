---
title: Redact tool secrets
description: Keep real secrets out of the agent while local tools still use them, via firma run shims.
---

[Inject credentials](../inject-credentials/) attaches a secret at the Sidecar for
**outbound HTTP** calls. This guide covers the other half: keeping secrets out of
the agent when it fetches them itself — from a **local tool** over stdio (a vault
CLI it runs), or from an **HTTP vault** it calls directly (a cloud secrets
manager). The agent only ever sees placeholders
(`firma-secret://<provider>/<name>`); the real values live in the `firma run`
broker, outside the sandbox.

Both are the same underlying mechanism — a `secret_providers` config entry
describing how to extract secrets — just triggered from two different
transports. Listing an entry in `secret_providers` is itself the
authorization to intercept; there is no separate policy step.

- **CLI (stdio)**: you list which executables to interpose on with a generic
  stdio **shim** that catches a vault CLI's stdout, replaces each secret with
  a placeholder, and keeps the real value in the broker. The agent's fetch
  returns placeholders.
- **HTTP vault**: the Sidecar's HTTPS MITM path intercepts the vault's
  response the same way the CLI shim intercepts stdout — see
  [HTTP vaults](#http-vaults) below.

A runnable CLI-shim example lives in
[`examples/firma-run/secret-redaction/`](https://github.com/openfirma/openfirma/tree/main/examples/firma-run/secret-redaction).

## When to use this vs other secret mechanisms

- The secret is a **static HTTP header** for an upstream host → use
  [credential injection](../inject-credentials/). The Sidecar attaches it at L7
  and the agent never holds it.
- The secret appears in an **HTTP request body** (JSON, form, raw) → use
  [secret placeholders](../secret-placeholders/). The agent writes a
  `firma-secret://` token; the Sidecar resolves it at dispatch time.
- The secret is produced or consumed by a **local process over stdio** (a vault
  CLI's output, a value an MCP tool needs) → use a CLI shim, described here.
- The secret comes from an **HTTP vault the agent calls directly** (a cloud
  secrets manager) → use an HTTP-shaped `secret_providers` entry, described in
  [HTTP vaults](#http-vaults) below.

They compose: injection guards the header boundary, placeholders guard the body
boundary, and shims guard the process I/O boundary. Secrets fetched via shims
(this guide) become the source for placeholder rehydration; the two mechanisms
are typically used together.

## Step 1: List the executables to shim

`secret_providers` is the only secret-specific setting in `firma.toml`. It
carries no behavior — just which commands to route through the broker. A bare
string names a built-in integration (`bws`, `op`, `vault`, `doppler`):

```toml
[run.defaults]
secret_providers = ["bws", "npx"]
```

Keep the list tight: every launch of a shimmed executable is mediated (routed
through the broker) unconditionally. Shimming a launcher like `npx` means
every `npx` invocation is mediated.

The shim is bound over the real binary's path, so absolute-path, renamed, or
copied invocations still hit it — not just `PATH` lookups.

A tool with no built-in integration needs a full table entry instead of a bare
name — it tells the broker how to extract secrets from the tool's output and
which placeholder template to mint. Full-table entries are tagged with
`type = "cli"` or `type = "http"` (see below) so a CLI-only field and an
HTTP-only field can never be mixed on the same entry. Entries of any shape can
be mixed in the same list:

```toml
[run.defaults]
secret_providers = [
    "bws",
    { type = "cli", name = "mock-vault", placeholder_template = "firma-secret://demo/{name}", matcher = { type = "json", value_path = "$[*].value", name_path = "$[*].key" } },
]
```

See
[`examples/firma-run/secret-redaction/firma.toml`](https://github.com/openfirma/openfirma/tree/main/examples/firma-run/secret-redaction/firma.toml)
for a complete custom-integration example.

## HTTP vaults

For a vault the agent calls directly over HTTPS (instead of via a CLI you
shim), use an HTTP-shaped `secret_providers` entry — `type = "http"` instead
of `type = "cli"`:

```toml
[run.defaults]
secret_providers = [
    {
        type = "http",
        provider_id = "aws-secrets-manager",
        host = "secretsmanager.*.amazonaws.com",
        placeholder_template = "firma-secret://aws/{name}",
        matcher = { type = "json", value_path = "$.SecretString", name_path = "$.Name" },
    },
]
```

`host` is a glob pattern (`*` matches one segment, same syntax as
[mapping rules](../../concepts/action-classes/)); `path` is an optional glob
pattern that defaults to matching any path on `host`. `matcher` and
`placeholder_template` work exactly like the CLI form.

There is no built-in HTTP vault — every HTTP provider is fully user-defined,
the same posture as a custom CLI integration like the `mock-vault` example
above.

No governance endpoint is needed for either form — a `secret_providers` entry
matching the request (by `host`/`path` for HTTP, by binary name for CLI) is
itself the authorization. For the HTTP form, the Sidecar evaluates the match
itself, since it is already on the MITM path for the response: it runs the
provider's matcher over the response body, mints a placeholder for each
extracted secret, and pushes it to the `firma run` broker (the same
out-of-sandbox dictionary the CLI form populates) — the agent only ever sees
the placeholder.

## The flow

**Fetch (intercept).** The agent runs `bws secret list`. The broker reads its
stdout, stores each value under `firma-secret://bitwarden/<key>`, and returns
output with every value replaced by its placeholder.

A placeholder only rehydrates if it is already in the dictionary, so the agent
must fetch a secret before it can use it. An unknown placeholder is left
untouched — the tool receives no secret.

## Invariants

- **Fail closed.** A broker error blocks the stream instead of forwarding
  plaintext or an unrehydrated placeholder.
- **Dictionary out-of-sandbox.** The placeholder ↔ secret map and all rewriting
  live in the broker; the in-sandbox shim holds no secrets.
- **Deterministic.** Behavior is a pure function of the `secret_providers`
  config plus the launch context, like the rest of OpenFirma enforcement.

## Sharp edges

- **The vault credential lives in the sandbox by design.** The vault CLI runs
  in-sandbox, so a token like `BWS_ACCESS_TOKEN` must be present there
  (`env_passthrough`). It is independent of the broker dictionary and never
  enters it.
- **Masking is best-effort.** A secret transformed before output (base64, hex,
  chunked, re-encoded) will not match and will not be masked. The primary
  control is that the agent only ever holds placeholders; stdout masking is
  defense-in-depth against a tool echoing a rehydrated value back.
- **Interactive/PTY tools are out of scope for now.** Pipe interposition breaks
  TTY detection; the current target is non-interactive tools (a vault CLI and an
  MCP server both qualify).
- **Platform.** Shims target the Linux `bwrap` backend first; the feature relies
  on Unix socket fd-passing.

## What's next

- [Inject credentials](../inject-credentials/) — the HTTP-boundary counterpart.
- [Concepts: The sandbox boundary](../../concepts/sandbox/) — where shims and the
  broker sit relative to the agent.
- Design detail: `docs/architecture/secrets-interception.md` in the repository.
