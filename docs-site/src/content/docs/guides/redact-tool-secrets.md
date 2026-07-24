---
title: Redact tool secrets
description: Keep real secrets out of the agent while local tools still use them, via firma run shims.
---

[Inject credentials](../inject-credentials/) attaches a secret at the Sidecar for
**outbound HTTP** calls. This guide covers the other half: keeping secrets out of
the agent when it fetches them itself — from a **local tool** over stdio (a vault
CLI it runs, or an MCP server it drives), or from an **HTTP vault** it calls
directly (a cloud secrets manager). The agent only ever sees placeholders
(`firma-secret://<provider>/<name>`); the real values live in the `firma run`
broker, outside the sandbox.

Both are the same underlying mechanism — a Cedar `secret.mediate` policy
authorizing a `Firma::SecretProvider` resource, plus a `secret_providers`
config entry describing how to extract secrets — just triggered from two
different transports:

- **CLI (stdio)**: you list which executables to interpose on with a generic
  stdio **shim**. There are two behaviors:
  - **intercept** — catch a vault CLI's stdout, replace each secret with a
    placeholder, and keep the real value in the broker. The agent's fetch
    returns placeholders.
  - **redact** — for a sanctioned tool, rehydrate placeholders into real
    secrets on its **stdin**, and mask real secrets back into placeholders on
    its **stdout**.
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

Keep the list tight: every launch of a shimmed executable pays a broker
round-trip, even when the policy leaves it untouched. Shimming a launcher like
`npx` means every `npx` invocation is mediated.

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

## Step 2: Write the `secret.mediate` policy

Behavior lives entirely in Cedar annotations, evaluated per launch. The
resource is a `Firma::SecretProvider` entity: `resource.id` is the resolved
provider identity (e.g. `"bitwarden"` for `bws` — the same string used in the
placeholder template), while `resource.bin`/`resource.args` carry the
invocation itself, so `like` matches against the arguments of a specific
launch.

```cedar
// Intercept the Bitwarden Secrets Manager CLI. Its `secret list` output is a
// JSON array of { key, value }; store each value under a placeholder.
@mode("intercept")
@matcher("json")
@match_value("$[*].value")
@match_name("$[*].key")
@placeholder("firma-secret://bitwarden/{name}")
permit (principal, action == Firma::Action::"secret.mediate", resource)
when { resource.bin == "bws" };

// Redact the Playwright MCP server (newline-delimited JSON-RPC over stdio).
@mode("redact")
@transform("mcp-jsonrpc")
permit (principal, action == Firma::Action::"secret.mediate", resource)
when { resource.bin == "npx" && resource.args like "@playwright/mcp*" };
```

Annotation reference:

- `@mode("intercept" | "redact")` — selects the behavior.
- `@matcher("json" | "regex")` (intercept only) — how to find secrets in the
  tool's output. `json` uses `@match_value` and `@match_name` (both required)
  as JSONPath; `regex` uses `@match_pattern` with `value` and `name` named
  capture groups.
- `@placeholder("firma-secret://…/{name}")` (intercept only) — the token
  template; `{name}` is filled with the matched key.
- `@transform("raw" | "mcp-jsonrpc")` (redact only) — the stream codec. Use
  `mcp-jsonrpc` for MCP stdio servers so rewriting stays inside JSON strings;
  `raw` is a byte-level streaming codec for unstructured tools.

Annotations are validated at bundle load: a bad JSONPath/regex, a missing
required directive, or a redact rule with a matcher **fails the whole bundle
closed**. Check a policy offline with `firma policy validate <file.cedar>`.

## Step 3: Point the broker at a governance endpoint

Per-launch `secret.mediate` decisions travel over the Sidecar's local-exec
governance socket — a local call, off the network hot path:

```toml
[run.profiles.playwright.sidecar_local_exec]
endpoint = "unix:///tmp/firma-sidecar-tools.sock"
timeout_ms = 600
```

Without this endpoint, shimmed launches **fail closed** (the tool is not run).

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

The Cedar policy uses the same `Firma::SecretProvider` resource and the same
`secret.mediate` action as the CLI form — only the populated attributes
differ: `resource.host`/`resource.path`/`resource.method` (the MITM'd
request) instead of `resource.bin`/`resource.args` (the CLI invocation).
`resource.id` is still the provider identity:

```cedar
permit (principal, action == Firma::Action::"secret.mediate", resource)
when { resource.id == "aws-secrets-manager" };
```

No governance endpoint is needed for the HTTP form (unlike the CLI form's
`sidecar_local_exec` requirement in Step 3) — the Sidecar evaluates the
policy itself, since it is already on the MITM path for the response. On a
Cedar permit, the Sidecar runs the provider's matcher over the response body,
mints a placeholder for each extracted secret, and pushes it to the `firma
run` broker (the same out-of-sandbox dictionary the CLI form populates) —
the agent only ever sees the placeholder.

## The flow

1. **Fetch (intercept).** The agent runs `bws secret list`. The broker reads its
   stdout, stores each value under `firma-secret://bitwarden/<key>`, and returns
   output with every value replaced by its placeholder.
2. **Use (redact).** The agent embeds a placeholder in a Playwright tool-call
   argument. On the server's stdin the broker rehydrates it into the real value
   inside the JSON-RPC message; on stdout any reflected secret is masked back.

A placeholder only rehydrates if it is already in the dictionary, so the agent
must fetch a secret before it can use it. An unknown placeholder is left
untouched — the tool receives no secret.

## Invariants

- **Fail closed.** A broker error, unreachable governance endpoint, or transform
  failure blocks the stream instead of forwarding plaintext or an unrehydrated
  placeholder.
- **Dictionary out-of-sandbox.** The placeholder ↔ secret map and all rewriting
  live in the broker; the in-sandbox shim holds no secrets.
- **Deterministic.** Behavior is a pure function of the Cedar bundle plus the
  launch context, like the rest of OpenFirma enforcement.

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
