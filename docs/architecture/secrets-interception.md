# Secret Interception and Redaction

Status: draft (design)\
Date: 2026-07-15\
Scope: `firma run` (broker + sandbox shims) and the Sidecar Cedar policy model;
no changes to the Sidecar network hot path

## Overview

This document specifies a `firma run` capability that keeps real secret values
out of the agent while still letting sanctioned tools use them. It has two
Cedar-driven behaviors:

- **intercept** — catch the agent's calls to a **vault CLI** (for example
  `bws`, the Bitwarden Secrets Manager CLI), replace each returned secret with a
  placeholder, and keep the real value in a firma-run-owned dictionary. The
  agent only ever sees placeholders.
- **redact** — for tools Cedar authorizes, rehydrate placeholders into real
  secrets on the tool's **stdin**, and mask real secrets back into placeholders
  on the tool's **stdout**. First target: a Playwright MCP server over stdio.

The two are one mechanism with different transforms: intercept _produces_
dictionary entries, redact _consumes_ them.

The mechanism is a **generic stdio interposition** ("shim"). Which executables
are shimmed is per-profile `firma.toml` config; **what a shim does** (intercept
vs redact, transform, placeholder, permit/deny) is decided by Cedar policy. The
config is therefore not secret-specific.

### Why stdio, not HTTP

The plaintext secret is materialized by the vault CLI **on its stdout**,
regardless of how the tool obtained it. A tool may fetch end-to-end-encrypted
ciphertext and decrypt locally (so an HTTPS MITM sees only ciphertext), or read a
local store or OS keychain (no network at all). Intercepting the tool's stdout is
therefore the one transport-agnostic point where the plaintext reliably appears —
so interception happens at the process I/O boundary, not the network boundary.

For example, `bws` performs client-side decryption: the Bitwarden API returns
ciphertext that `bws` decrypts locally, so the cleartext secret exists only on the
`bws` process's stdout.

## Key Invariants

- **Fail closed.** A broker error, unreachable broker, or transform failure
  blocks the stream (non-zero exit); it never forwards plaintext or an
  unrehydrated placeholder by default.
- **Dictionary out-of-sandbox.** The placeholder ↔ secret dictionary and all
  substitution logic live in the firma-run broker, outside the sandbox. Shims
  hold no secrets.
- **Least exposure.** Real plaintext appears in the sandbox only transiently, on
  one specific tool's stdio fd (unavoidable: the vault CLI writes it, or a
  sanctioned tool reads it). It is never materialized in the agent process or a
  shim.
- **Deterministic policy.** Behavior is a pure function of the Cedar bundle plus
  the launch context, consistent with the rest of OpenFirma enforcement.

## Architecture

```
                          sandbox boundary
  agent ── spawns ──▶ shim (fd-courier, no secrets)
                        │  socketpair + SCM_RIGHTS over UDS bridge
                        ▼
                     ┌───────────────────────────────────┐
                     │  firma-run broker (out-of-sandbox) │
                     │   • secrets dictionary             │
                     │   • pluggable transform            │
                     │   • fd multiplexing / rewrite      │
                     └───────────────┬───────────────────┘
                                     │ governance request (per launch)
                                     ▼
                             Sidecar (Cedar PDP)
```

Three pieces:

1. **Broker** — a component in the firma-run host process. Owns the in-memory
   dictionary (placeholder → value, plus an Aho-Corasick matcher over values for
   masking) and performs every rewrite. It is the policy _enforcement_ point
   (PEP): at each shimmed-tool launch it asks the Sidecar for a decision, then
   applies it.
2. **Shims** — thin executables injected into the sandbox that shadow the
   configured commands. Reuse the existing PATH-shim pattern
   (`runtime/vscode.rs` `prepend_path`). A shim connects to the broker over the
   UDS bridge, makes a `socketpair` for the wrapped tool, passes the fds to the
   broker via `SCM_RIGHTS`, execs the real tool, then waits and propagates
   exit/signals. It is **role-agnostic** — the broker learns the behavior from
   the Cedar decision — and holds no plaintext.
3. **UDS bridge + fd passing** — shims reach the broker over a Unix socket
   bind-mounted into the sandbox (the existing `FIRMA_RUN_PROXY_BRIDGE_*`
   plumbing). Passing fds via `SCM_RIGHTS` has precedent in the egress guard.

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

## Policy Model: PDP / PEP

Cedar decisions are evaluated **only in the Sidecar** (`CedarPolicyEvaluator`),
fed by signed bundles from the Authority. firma-run has no Cedar evaluator, so
the broker (PEP) consults the Sidecar (PDP) over the existing local-exec
governance channel (`command-governance-local-exec-contract.md`), which already
carries an allow/deny/pending_hitl decision request per launch. This is a
per-launch call over a local socket — off the network hot path — not per-byte.

### Action and annotations

A single action expresses "may this shimmed launch be mediated, and how":

```cedar
@mode("intercept")
@adapter("bws")
@placeholder("firma-secret://bitwarden/{name}")
permit(principal, action == Firma::Action::"secret.mediate", resource)
when { resource.id like "bws *" };

@mode("redact")
@transform("mcp-jsonrpc")
@placeholder("firma-secret://bitwarden/{name}")
permit(principal, action == Firma::Action::"secret.mediate", resource)
when { resource.id like "npx @playwright/mcp*" };
```

- `resource.id` is the launch argv (the broker sends it in the governance
  request); `like` provides prefix/glob matching, as already used for
  host/path rules.
- Annotations carry the behavior, parsed at bundle-load into the remediation map
  exactly as `@modify`/`@step_up`/`@defer` are today:
  - `@mode("intercept"|"redact")` — selects the broker topology.
  - `@transform("raw"|"mcp-jsonrpc")` — stream codec (redact).
  - `@adapter("<name>")` — vault-output parser (intercept), e.g. `bws`.
  - `@placeholder("…")` — placeholder template.

### Decision semantics (fail-closed)

- **Broker cannot reach the Sidecar** → **deny** (block the launch).
- **Sidecar returns forbid / no matching policy** → transparent **passthrough**:
  the binary is a shim candidate but is not governed, so it runs untouched.
- **Malformed or incomplete annotations** (e.g. `@mode("redact")` without
  `@transform`, or `@mode("intercept")` without `@adapter`) → **reject the
  bundle at load**, like a malformed `@modify` today.
- **All `@placeholder` values must agree** across policies (validated at load)
  so dictionary keys stay consistent.

## Placeholder Format

```
firma-secret://<provider>/<name>
```

- `<provider>` is the vault namespace (for example `bitwarden`), chosen by the
  policy's `@placeholder` template; `<name>` is the secret's key.
- Prefix-anchored: match the fixed `firma-secret://`, then consume the maximal
  run of `[A-Za-z0-9._/-]` (any other byte is percent-encoded at mint time). The
  boundary is defined by the charset — no end sentinel needed.
- ASCII, shell- and JSON-safe, and stable through an LLM round-trip.
- Legible: the agent and operators can see which secret a reference points to.
- Fail-closed: a mangled token yields no dictionary hit, so the literal passes
  through and the tool receives no secret — never a leak.
- `<name>` is the secret's **key** as read from the vault CLI's output. Vault
  CLIs commonly address secrets by an opaque id (e.g. `bws secret get <uuid>`),
  so the adapter records an id→key mapping when minting; key collisions are
  disambiguated only if they actually occur.

The full token (including prefix) is the dictionary key; the rewriter never has
to parse `<name>` semantically.

## Transform Layer

The broker applies the transform named by the decision's `@transform` (redact)
or the `@adapter`'s built-in output handling (intercept):

- **`raw`** — streaming byte matcher. Carries an overlap buffer of
  `maxTokenLen - 1` (rehydration) or `maxSecretLen - 1` (masking) across reads so
  a token/secret split across chunk boundaries still matches.
- **`mcp-jsonrpc`** — newline-delimited JSON-RPC codec for MCP stdio servers.
  Parses each message and substitutes in JSON context:
  - rehydration **JSON-escapes** the secret so quotes/backslashes/newlines cannot
    corrupt the message;
  - masking matches secrets in their **JSON-escaped** on-wire form.

  Raw byte substitution is unsafe for MCP: unescaped secrets produce invalid
  JSON, and escaped secrets on stdout would be missed by a literal search.

## Mode: intercept

The vault CLI runs **in-sandbox** as a normal agent subprocess (it is called by
the agent). Any credential it needs is already present in the sandbox.

```
agent: `<vault-cli> get <ref>`          # e.g. `bws secret get <uuid>`
  └─ shim: execs the real vault CLI in-sandbox,
       wires its stdout → socketpair → SCM_RIGHTS → broker
  └─ broker: reads the plaintext stdout,
       extracts value(s) via the @adapter parser,
       stores value ↔ firma-secret://<provider>/<name>,
       forwards placeholder-substituted output → agent
```

The adapter is tool- and subcommand-aware. Only **stdout** is transformed.

## Mode: redact

```
agent ──▶ shim ──SCM_RIGHTS──▶ broker ──▶ T.stdin   [rehydrate: placeholder→secret]
agent ◀── shim ◀──SCM_RIGHTS── broker ◀── T.stdout  [mask: secret→placeholder]
```

### First target: Playwright MCP server

The agent (MCP client) spawns the Playwright MCP server as a stdio subprocess and
embeds `firma-secret://<provider>/<name>` in a tool-call argument (for example, a
login value). On the server's stdin the broker rehydrates the placeholder inside
the JSON-RPC message, so Playwright drives the browser with the real value; the
agent never held it. On stdout, any secret reflected in page content or DOM is
masked back to its placeholder.

MCP servers typically launch via `npx` / `node` / `docker`, so the shim shadows
the launcher (coarse), and Cedar's `resource.id like` selects the exact
invocation to govern (fine).

## Secret Lifecycle

The dictionary is populated **only by intercept** — that is, only when the agent
calls a vault CLI. redact rehydrates a placeholder only if it is already in the
dictionary; an unknown placeholder on stdin **fails closed** (the literal is not
substituted, so the tool receives no secret). The broker never contacts the vault
itself, so the vault CLI stays in-sandbox and no vault credentials live in the
broker. Consequence: the agent must fetch a secret via the vault CLI before it can
use the corresponding placeholder in a redact target.

The dictionary is run-scoped and zeroized on teardown.

## Configuration

`firma.toml` holds only the mechanism residue: which executables to interpose on,
per profile. Everything else is Cedar. Profiles live under `[run.profiles.<name>]`
and merge over `[run.defaults]`.

```toml
[run.defaults]
shims = ["bws"]              # baseline for every profile

[run.profiles.playwright-agent]
shims = ["bws", "npx"]       # this profile also shadows npx
```

`shims` is a `Vec<String>` on the profile patch (like `env_passthrough` /
`allowed_executables`). It is **distinct** from two existing mechanisms:

- `executable_policies.<name>` rewrites _argv_ (e.g. injecting flags for codex);
- the built-in `vscode` shim shadows `code`.

`shims` here is **stdio interposition routed to the broker**. It carries no
behavior — Cedar decides intercept vs redact and all directives — so the config
is not secret-specific and could drive other shim behaviors in future.

## Threat Model and Caveats

- **Broker is the trust anchor.** All plaintext and the dictionary live there,
  out-of-sandbox. Secrets are zeroized on drop; the dictionary is run-scoped.
- **Residual redact exposure.** A sanctioned tool `T` receives real plaintext on
  its stdin (it must, to function). A hostile agent could `ptrace` that specific
  `T` to observe a secret — but only secrets it itself chose to route into `T`,
  and it cannot enumerate the dictionary or read other secrets.
- **Vault credential in-sandbox.** Accepted: the vault CLI runs in-sandbox by
  design, so any credential it needs (e.g. `bws`'s `BWS_ACCESS_TOKEN`) is present
  there. This is independent of the dictionary, which stays in firma-run.
- **Masking is best-effort (by design).** Secrets transformed before output
  (base64, hex, chunked, re-encoded) will not match. This is accepted: the
  primary control is that the agent never sees the secret (placeholders only);
  stdout masking is defense-in-depth against a tool echoing a rehydrated value
  back, not a guarantee.
- **Coarse shadowing cost.** Shadowing `npx` means every `npx` launch pays a
  shim + governance round-trip, even ungoverned ones (which then pass through).
  Keep `shims` lists tight.
- **Vault-CLI egress.** If the vault CLI reaches a network backend, that traffic
  (with the CLI in-sandbox) traverses the Sidecar, so the egress policy must
  permit the vault's API host (e.g. Bitwarden's). The Sidecar sees only
  ciphertext, so nothing changes on the interception side.

## Sharp Edges

- **Interactive / PTY tools.** Pipe interposition breaks TTY detection. v1
  targets non-interactive tools (the vault CLI and the MCP server both qualify);
  PTY allocation is deferred to hardening.
- **Large payloads.** MCP responses (base64 screenshots, full DOM) can be large;
  per-line JSON parse cost is acceptable but noted.
- **Chunk boundaries.** The `raw` transform must not miss a token/secret split
  across reads (overlap buffer); covered by property tests.
- **Exit and signal fidelity.** The shim must propagate the wrapped tool's exit
  code and forward signals (reuse `supervisor.rs`).

## Resolved Decisions

- **Resolution model: intercept-only.** The dictionary is populated only via a
  vault CLI; redact fails closed on unknown placeholders; no broker-side vault
  access (see Secret Lifecycle).
- **Masking: best-effort** defense-in-depth (see Threat Model).
- **Placeholder `<name>`: the secret key** read from the vault CLI's output, via
  an id→key mapping (see Placeholder Format).

## Phased Plan

Each phase is an atomic revision that stands on its own, with tests per
`rust-tests-guidelines`.

| Phase | Scope | Crates | Outcome |
| ----- | ----- | ------ | ------- |
| 0 | This design doc; governance-contract extension; placeholder format | docs | Reviewed |
| 1 | Broker skeleton: dictionary, Aho-Corasick matcher, UDS listener, `SCM_RIGHTS` fd-passing (no rewrite) | firma-run (+core types) | Unit tests: dictionary, matcher |
| 2 | Cedar: `secret.mediate` action class + `@mode`/`@transform`/`@adapter`/`@placeholder` annotations, remediation-map parsing, load-time validation | firma-core (schema), firma-sidecar | Unit tests on annotation parse/validate |
| 3 | Governance-contract extension: broker → Sidecar decision returning mode + directives; PEP wiring; fail-closed rules | firma-run, firma-sidecar | E2E decision round-trip |
| 4 | intercept: vault-CLI shim + broker + first adapter (`bws`) + minting | firma-run | E2E on bwrap with a fake vault CLI |
| 5 | Transform layer: `raw` streaming rewriter (rehydrate + mask) with overlap buffers; fd-courier shim | firma-run | Property tests on chunk splits |
| 6 | `mcp-jsonrpc` transform: line framing, JSON-aware rehydrate/mask/escape | firma-run | Unit tests on escaped/split cases |
| 7 | redact + `shims` config + PATH-shim/bind-over-path injection; Playwright MCP integration; docs (docs-site + llms.txt) | firma-run, config-loader, docs | `just check` green |
| 8 | Hardening: PTY/interactive, perf, zeroization; later — other backends (macOS vz-guest / WSL) and more vault CLIs | firma-run, backends | — |

## Cross-Platform Notes

The shim + UDS + `SCM_RIGHTS` model targets the Linux `bwrap` backend first. VM
backends (macOS `vz` guest, future Firecracker) already funnel stdio through a
narrow vsock channel; the broker connection would ride that channel, with the
rewrite still host-side. WSL2-from-Windows can pipe `wsl.exe` stdio. Post-v1.

## Open Follow-ups

- Additional vault CLIs (`bw`, `op`, `vault`) via new `@adapter` values.
- HTTP-transport MCP (SSE) would instead traverse the Sidecar and hit the
  response-path-enforcement gap tracked in `docs/security/bypass-risks.md`.
- Whether `secret.mediate` should split into `secret.resolve` / `secret.inject`
  verbs (resolved Sidecar-side) instead of a single action + `@mode`.
