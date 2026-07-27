# Secret Interception and Redaction

Status: draft (design), updated to match shipped behavior\
Date: 2026-07-15 (original), updated 2026-07-27\
Scope: `firma run` (broker + sandbox shims) and the Sidecar's HTTP redact
path; no changes to the Sidecar network hot path

> This document originally proposed a Cedar-annotation-driven authorization
> model for intercept (a `secret.mediate` action with `@mode`/`@matcher`/
> `@placeholder`/`@transform` annotations) and a stdio-based redact mode for
> locally spawned tools such as an MCP server. Neither shipped in that form.
> The content below has been updated to describe what was actually built —
> see [`fir-429-pai-credential-injection.md`](fir-429-pai-credential-injection.md)
> for the fuller, actively-maintained design (including HTTP vaults).
> Stdio-based redact (rehydrating/masking on a locally spawned tool's stdin/
> stdout, e.g. an MCP server) was never implemented; intra-sandbox traffic
> does not traverse the Sidecar and remains a known gap tracked in
> `docs/security/bypass-analysis.md`.

## Overview

This document specifies a `firma run` capability that keeps real secret values
out of the agent while still letting sanctioned tools use them. It covers two
behaviors:

- **intercept** — catch the agent's calls to a **vault CLI** (for example
  `bws`, the Bitwarden Secrets Manager CLI) over stdio, or a vault's response
  over HTTP, replace each returned secret with a placeholder, and keep the
  real value in a firma-run-owned dictionary. The agent only ever sees
  placeholders.
- **redact** — for outbound HTTP calls Cedar authorizes, rehydrate
  placeholders into real secrets in the request, and mask real secrets back
  into placeholders in the response. This is the Sidecar's existing MITM
  path; see `fir-429-pai-credential-injection.md` for the full design.

Intercept and redact are one mechanism with different transforms: intercept
_produces_ dictionary entries, redact _consumes_ them.

Intercept is a **generic interposition** mechanism: stdio (a shim) for CLI
vaults, HTTPS MITM for HTTP vaults. Which executables are shimmed, and which
HTTP hosts/paths are treated as vaults, is per-profile `firma.toml`
config — listing an entry in `secret_providers` is itself the authorization
to intercept it. **No Cedar policy gates intercept.** Cedar continues to
gate redact only (`secret.redact`, per outbound HTTP destination).

### Why stdio, not HTTP, for CLI vaults

The plaintext secret is materialized by the vault CLI **on its stdout**,
regardless of how the tool obtained it. A tool may fetch end-to-end-encrypted
ciphertext and decrypt locally (so an HTTPS MITM sees only ciphertext), or read a
local store or OS keychain (no network at all). Intercepting the tool's stdout is
therefore the one transport-agnostic point where the plaintext reliably appears —
so interception happens at the process I/O boundary for CLI vaults, not the
network boundary. (A vault reached directly over HTTP is intercepted on the
Sidecar's own MITM path instead — see `fir-429-pai-credential-injection.md`.)

For example, `bws` performs client-side decryption: the Bitwarden API returns
ciphertext that `bws` decrypts locally, so the cleartext secret exists only on the
`bws` process's stdout.

## Key Invariants

- **Fail closed.** A broker error or extraction failure blocks the stream
  (non-zero exit or unmodified passthrough); it never forwards plaintext by
  mistake.
- **Dictionary out-of-sandbox.** The placeholder ↔ secret dictionary and all
  substitution logic live in the firma-run broker, outside the sandbox. Shims
  hold no secrets.
- **Least exposure.** Real plaintext appears in the sandbox only transiently,
  on the vault CLI's stdout. It is never materialized in the agent process or
  the shim.
- **Deterministic.** Behavior is a pure function of the `secret_providers`
  config (intercept) or the Cedar bundle (redact) plus the launch/request
  context, consistent with the rest of OpenFirma enforcement.

## Architecture

```
                        sandbox boundary
agent ── spawns ──▶ shim (fd-courier, no secrets)
                      │  socketpair + SCM_RIGHTS over UDS bridge
                      ▼
                   ┌───────────────────────────────────┐
                   │  firma-run broker (out-of-sandbox) │
                   │   • secrets dictionary             │
                   │   • per-provider matcher           │
                   │   • fd multiplexing / rewrite      │
                   └─────────────────────────────────---┘
```

A binary reaching the broker at all is proof it matched a configured
`secret_providers` entry — that's why the shim was installed over it — so
there is no separate per-launch decision to make.

Two pieces:

1. **Broker** — a component in the firma-run host process. Owns the in-memory
   dictionary (placeholder → value, plus an Aho-Corasick matcher over values for
   masking) and performs every rewrite for the CLI-shim origin. Runs the real
   vault CLI out-of-sandbox and applies the configured matcher — there is no
   separate policy decision to consult.
2. **Shims** — thin executables injected into the sandbox that shadow the
   configured commands. Reuse the existing PATH-shim pattern
   (`runtime/vscode.rs` `prepend_path`). A shim connects to the broker over the
   UDS bridge, makes a `socketpair` for the wrapped tool, passes the fds to the
   broker via `SCM_RIGHTS`, execs the real tool, then waits and propagates
   exit/signals. It holds no plaintext.

Shims reach the broker over a Unix socket bind-mounted into the sandbox (the
existing `FIRMA_RUN_PROXY_BRIDGE_*` plumbing). Passing fds via `SCM_RIGHTS`
has precedent in the egress guard.

### Why shim + bind-over-path, not pure syscall interception

Intercepting `execve` (seccomp user-notify) is **allow/deny only** — it cannot
redirect a child's fds or rewrite argv, so it cannot route stdio through the
out-of-sandbox broker. `ptrace` could, but only by puppeteering an uncooperative
process from outside (fragile, slow, fights the sandbox). A shim is simply a
process we control in the child's own startup path, where constructing the fd
topology is trivial.

The shim is made **unavoidable** by mounting it over the real binary path
(`--ro-bind` of the shim onto e.g. `/usr/bin/bws`) so absolute-path, renamed, or
copied invocations still hit the shim; classic PATH shadowing alone would miss
them.

Note: this gate is **filesystem-based (bind-over-path)**, not seccomp. Classic
seccomp BPF cannot match `execve`'s pathname (it is a pointer the filter cannot
dereference), so a `system.execute` deny would block _all_ exec, not a specific
binary. Per-path exec gating is only possible via seccomp **user-notify +
`process_vm_readv`** (egress-guard style) and is optional defense-in-depth, not
required for correctness.

## Configuration Model

All behavior lives in `firma.toml`'s `secret_providers` list — there is no
Cedar policy for intercept. Each entry is either a bare string (a built-in
integration, keyed by binary name) or a full table tagged `type = "cli"` or
`type = "http"`:

```toml
[run.defaults]
secret_providers = [
  "bws", # built-in integration, matched by binary name
  { type = "cli", name = "my-vault", provider_id = "my-vault", matcher = { type = "json", value_path = "$[*].value", name_path = "$[*].key" }, placeholder_template = "firma-secret://my-vault/{name}" },
  { type = "http", provider_id = "aws-secrets-manager", host = "secretsmanager.*.amazonaws.com", matcher = { type = "json", value_path = "$.SecretString", name_path = "$.Name" }, placeholder_template = "firma-secret://aws/{name}" },
]
```

A `type = "cli"` entry's key is the binary name shimmed in the sandbox
(bind-mounted over the real executable). A `type = "http"` entry's `host`
(and optional `path`) are glob patterns matched against the Sidecar's view
of the outbound request. Both shapes carry the same `matcher` /
`placeholder_template` fields — how to extract `(name, value)` pairs from the
tool's output or the HTTP response body, and how to mint the placeholder
token. A CLI entry may also carry `credential_env_vars`, `strip_arg_flags`,
and `forced_args`.

Listing an entry is itself the authorization: the broker (CLI origin) or the
Sidecar (HTTP origin) mediates every matching launch/response
unconditionally. There is no permit/forbid decision to author.

### Decision semantics (fail-closed)

- A shim/HTTP-provider entry being configured is itself the authorization to
  intercept — every matching launch/response is mediated unconditionally.
- Sidecar: no matching `secret.redact` policy → passthrough (forward
  outbound HTTP unchanged).
- Sidecar: `forbid` on `secret.redact` → deny.
- Unknown `integration` name in `firma.toml` → startup error.

## Placeholder Format

```
firma-secret://<provider>/<name>
```

- `<provider>` is the vault namespace (for example `bitwarden`), chosen by
  the entry's `placeholder_template`; `<name>` is the secret's key.
- Prefix-anchored: match the fixed `firma-secret://`, then consume the maximal
  run of `[A-Za-z0-9._/-]` (any other byte is percent-encoded at mint time). The
  boundary is defined by the charset — no end sentinel needed.
- ASCII, shell- and JSON-safe, and stable through an LLM round-trip.
- Legible: the agent and operators can see which secret a reference points to.
- Fail-closed: a mangled token yields no dictionary hit, so the literal passes
  through and the tool receives no secret — never a leak.
- `<name>` is the secret's **key**, produced by the intercept matcher — a
  JSONPath name node or a regex `name` capture group. Cross-key
  collisions are disambiguated only if they actually occur.

The full token (including prefix) is the dictionary key; the rewriter never has
to parse `<name>` semantically.

## Matcher (intercept)

Intercept extraction is driven by the entry's `matcher` config, compiled and
executed by the shared `firma-secret-provider` matcher type (used by both the
firma-run broker for the CLI origin and `firma-sidecar` for the HTTP origin):

- **`json`** — JSONPath (`serde_json_path`). `value_path` / `name_path`
  select aligned value/name nodes; the value nodes are replaced **structurally**
  (via JSON pointer), so escaping is never an issue. Handles single objects,
  arrays, and nested shapes.
- **`regex`** — a pattern with required `value` and `name` named capture
  groups extracts each secret from text output; the `value` spans are
  replaced in place.

Each extracted `(name, value)` is minted into a placeholder (from the entry's
`placeholder_template`) and stored; the value is replaced by the placeholder
in the returned output. A tool is never special-cased in code — a new vault
CLI or HTTP vault is just a new `secret_providers` entry.

Redact (outbound HTTP only) uses a separate Content-Type–driven rewriter
(`raw`/`json`/`form`/`xml`) in the Sidecar's MITM path; see
`fir-429-pai-credential-injection.md` for that mechanism. Stdio-based redact
for a locally spawned tool (rehydrating on stdin / masking on stdout) is not
implemented.

## Mode: intercept

The vault CLI runs **in-sandbox** as a normal agent subprocess (it is called by
the agent). Any credential it needs is already present in the sandbox.

```
agent: `<vault-cli> get <ref>`          # e.g. `bws secret get <uuid>`
  └─ shim: execs the real vault CLI in-sandbox,
       wires its stdout → socketpair → SCM_RIGHTS → broker
  └─ broker: reads the plaintext stdout,
       extracts value(s) via the configured matcher (JSONPath / regex),
       stores value ↔ firma-secret://<provider>/<name>,
       forwards placeholder-substituted output → agent
```

The matcher is config-defined (`secret_providers` entry); no tool is
special-cased in code. Only **stdout** is transformed.

An HTTP vault follows the same shape but on the Sidecar's own MITM path
instead of a shim — see `fir-429-pai-credential-injection.md`.

## Secret Lifecycle

The dictionary is populated only by intercept (CLI or HTTP origin) — that is,
only when the agent calls a vault CLI or a vault HTTP endpoint it's
configured to intercept. Redact rehydrates a placeholder in an outbound HTTP
request only if it is already in the dictionary; an unknown placeholder
**fails closed** (the literal is not substituted, so the upstream receives no
secret). The broker never contacts the vault on its own initiative, so the
vault CLI stays in-sandbox and no vault credentials live in the broker.
Consequence: the agent must fetch a secret via the vault CLI/HTTP vault
before it can use the corresponding placeholder elsewhere.

The dictionary is run-scoped and zeroized on teardown.

## Threat Model and Caveats

- **Broker is the trust anchor.** All plaintext and the dictionary live there,
  out-of-sandbox. Secrets are zeroized on drop; the dictionary is run-scoped.
- **Vault credential in-sandbox.** Accepted: the vault CLI runs in-sandbox by
  design, so any credential it needs (e.g. `bws`'s `BWS_ACCESS_TOKEN`) is present
  there. This is independent of the dictionary, which stays in firma-run.
- **Masking is best-effort (by design).** Secrets transformed before output
  (base64, hex, chunked, re-encoded) will not match. This is accepted: the
  primary control is that the agent never sees the secret (placeholders only);
  stdout masking on the redact path is defense-in-depth against a tool echoing
  a rehydrated value back, not a guarantee.
- **Coarse shadowing cost.** Shadowing a launcher like `npx` means every
  launch is mediated unconditionally. Keep `secret_providers` lists tight.
- **Vault-CLI egress.** If the vault CLI reaches a network backend, that traffic
  (with the CLI in-sandbox) traverses the Sidecar, so the egress policy must
  permit the vault's API host (e.g. Bitwarden's). The Sidecar sees only
  ciphertext, so nothing changes on the interception side.

## Sharp Edges

- **Interactive / PTY tools.** Pipe interposition breaks TTY detection; the
  current target is non-interactive tools. PTY allocation is deferred to
  hardening.
- **Exit and signal fidelity.** The shim must propagate the wrapped tool's exit
  code and forward signals (reuse `supervisor.rs`).
- **Stdio-based redact is unimplemented.** Intra-sandbox traffic (e.g. agent
  ↔ a locally spawned MCP server) does not traverse the Sidecar; redact is
  only available on the outbound-HTTP path. This is a known gap tracked in
  `docs/security/bypass-analysis.md`.

## Resolved Decisions

- **Resolution model: intercept-only for the dictionary.** The dictionary is
  populated only via a vault CLI or HTTP vault; redact fails closed on
  unknown placeholders; no broker-side vault access (see Secret Lifecycle).
- **Masking: best-effort** defense-in-depth (see Threat Model).
- **Placeholder `<name>`: the secret key** read from the vault's output, via
  the configured matcher (see Placeholder Format).
- **Authorization: config presence, not Cedar.** A `secret_providers` entry
  existing is itself the authorization to intercept — no permit/forbid
  decision, no per-launch round-trip to the Sidecar.

## Cross-Platform Notes

The shim + UDS + `SCM_RIGHTS` model targets the Linux `bwrap` backend first. VM
backends (macOS `vz` guest, future Firecracker) already funnel stdio through a
narrow vsock channel; the broker connection would ride that channel, with the
rewrite still host-side. WSL2-from-Windows can pipe `wsl.exe` stdio.

## Open Follow-ups

- Additional vault CLIs (`bw`, `op`, `vault`) or HTTP vaults are just new
  `secret_providers` entries — no code changes.
- HTTP-transport MCP (SSE) would traverse the Sidecar and hit the
  response-path-enforcement gap tracked in `docs/security/bypass-analysis.md`.
- Stdio-based redact for locally spawned tools (e.g. an MCP server) remains
  unimplemented; see Sharp Edges.
