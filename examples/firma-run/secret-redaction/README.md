# Secret interception & redaction

Keep real secret values out of the agent while still letting sanctioned tools
use them. The agent only ever sees placeholders (`firma-secret://…`); the real
values live in the `firma run` broker, out of the sandbox.

Full design: [`docs/architecture/secrets-interception.md`](../../../docs/architecture/secrets-interception.md).

## Files

- `firma.toml` — run profile. `shims` lists the executables to interpose on;
  `[authority]` tells `firma run` to auto-start a per-process Authority +
  Sidecar that loads the Cedar policy below.
- `policies/secret-mediation.cedar` — the `secret.mediate` policy: an
  **intercept** rule for the mock vault CLI and a **redact** rule for the mock
  MCP server. No external policy store required.
- `scripts/mock-vault` — stand-in for a vault CLI (`bws`, `op`, …). Outputs a
  JSON array of `{ key, value }` objects; the broker intercepts its stdout and
  replaces each value with a `firma-secret://` placeholder.
- `scripts/mock-mcp-server` — stand-in for an MCP server. Speaks
  newline-delimited JSON-RPC over stdio; the broker rehydrates placeholders on
  its stdin and masks reflected secrets on its stdout.
- `scripts/agent.py` — simulated agent that runs inside the sandbox. It calls
  `mock-vault` (step 1: intercept) and then `mock-mcp-server` (step 2: redact),
  asserting it only ever handles placeholder tokens.
- `run.sh` — orchestrates the demo end-to-end.

## The flow

1. **Fetch (intercept).** The agent calls `mock-vault`. The shim routes its
   stdout through the broker, which matches the policy's JSONPath, stores each
   value under `firma-secret://demo/<key>`, and gives the agent output with
   every value replaced by its placeholder. The agent never sees a real secret.

2. **Use (redact).** The agent calls `mock-mcp-server` with a placeholder (for
   example `firma-secret://demo/login-password`) in a `tools/call` argument.
   On the server's stdin the broker rehydrates the placeholder into the real
   value inside the JSON-RPC message; on stdout any reflected secret is masked
   back to its placeholder.

Ordering matters: a placeholder only rehydrates if it is already in the
dictionary, so the agent must fetch a secret (step 1) before it can use it
(step 2). An unknown placeholder is left untouched — the tool receives no
secret (fail closed).

## Running it

```sh
cargo build -p firma --release
examples/firma-run/secret-redaction/run.sh
```

`run.sh` checks for `python3` and `bwrap`, then calls `firma run` which
auto-starts an Authority + Sidecar loaded with the Cedar policy. The signing
key is generated on demand under `$XDG_RUNTIME_DIR` and is never committed.

To use this with a real vault CLI or MCP server, add the executable to `shims`
and update the `secret.mediate` rules in the Cedar policy — no code changes.

## Invariants

- **Fail closed.** A broker error, unreachable Sidecar, or transform failure
  blocks the stream rather than forwarding plaintext or an unrehydrated
  placeholder.
- **Dictionary out-of-sandbox.** The placeholder ↔ secret map and all rewriting
  live in the broker; the in-sandbox shim holds no secrets.
- **Masking is best-effort.** A secret transformed before output (base64, hex,
  chunked) will not be masked; the primary control is that the agent only ever
  holds placeholders.

## Adding another vault CLI or tool

No code changes: add the executable to `shims` and write a matching
`secret.mediate` rule. A new vault CLI is a new `@matcher` (JSONPath or regex);
a new redact target is a new `@transform` rule keyed on its `resource.id`.
