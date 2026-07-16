---
title: Redact tool secrets
description: Keep real secrets out of the agent while local tools still use them, via firma run shims.
---

[Inject credentials](../inject-credentials/) attaches a secret at the Sidecar for
**outbound HTTP** calls. This guide covers the other half: keeping secrets out of
the agent when it talks to **local tools** over stdio — a vault CLI it runs, or an
MCP server it drives. The agent only ever sees placeholders
(`firma-secret://<provider>/<name>`); the real values live in the `firma run`
broker, outside the sandbox.

The mechanism is a generic stdio **shim**. You list which executables to
interpose on in `firma.toml`; a Cedar `secret.mediate` policy decides what each
shim does. There are two behaviors:

- **intercept** — catch a vault CLI's stdout, replace each secret with a
  placeholder, and keep the real value in the broker. The agent's fetch returns
  placeholders.
- **redact** — for a sanctioned tool, rehydrate placeholders into real secrets on
  its **stdin**, and mask real secrets back into placeholders on its **stdout**.

A runnable example lives in
[`examples/firma-run/secret-redaction/`](https://github.com/openfirma/openfirma/tree/main/examples/firma-run/secret-redaction).

## When to use this vs credential injection

- The secret is an **HTTP credential** for an upstream host → use
  [credential injection](../inject-credentials/). The Sidecar attaches it at L7
  and the agent never holds it.
- The secret is produced or consumed by a **local process over stdio** (a vault
  CLI's output, a value an MCP tool needs) → use shims, described here.

They compose: injection guards the network boundary, shims guard the process I/O
boundary.

## Step 1: List the executables to shim

`shims` is the only secret-specific setting in `firma.toml`. It carries no
behavior — just which commands to route through the broker:

```toml
[run.defaults]
shims = ["bws", "npx"]
```

Keep the list tight: every launch of a shimmed executable pays a broker
round-trip, even when the policy leaves it untouched. Shimming a launcher like
`npx` means every `npx` invocation is mediated.

The shim is bound over the real binary's path, so absolute-path, renamed, or
copied invocations still hit it — not just `PATH` lookups.

## Step 2: Write the `secret.mediate` policy

Behavior lives entirely in Cedar annotations, evaluated per launch. `resource.id`
is the launch argv, so `like` matches the invocation.

```cedar
// Intercept the Bitwarden Secrets Manager CLI. Its `secret list` output is a
// JSON array of { key, value }; store each value under a placeholder.
@mode("intercept")
@matcher("json")
@match_value("$[*].value")
@match_name("$[*].key")
@placeholder("firma-secret://bitwarden/{name}")
permit (principal, action == Firma::Action::"secret.mediate", resource)
when { resource.id like "bws *" };

// Redact the Playwright MCP server (newline-delimited JSON-RPC over stdio).
@mode("redact")
@transform("mcp-jsonrpc")
permit (principal, action == Firma::Action::"secret.mediate", resource)
when { resource.id like "npx @playwright/mcp*" };
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
