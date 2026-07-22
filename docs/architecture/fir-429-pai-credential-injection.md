# FIR-429 — PAI Credential Injection

Status: draft (design)\
Date: 2026-07-20\
Scope: `firma run` (broker + sandbox shims), `firma-sidecar` (Cedar evaluation +
secret matcher + HTTP redact path), `firma-core` (decision types)

## Problem

An AI agent that calls a vault CLI (e.g. `bws`, `op`, `vault`, `doppler`)
receives the plaintext secret on the CLI's stdout. From that point the secret
lives in the agent process's memory, can appear in LLM context, and is trivially
exfiltrated via any outbound call the agent makes.

Two independent weaknesses compound this:

1. **The secret itself** is visible to the agent.
2. **The vault credential** (e.g. `BWS_ACCESS_TOKEN`, `OP_SERVICE_ACCOUNT_TOKEN`)
   is present in the sandbox environment, so the agent could bypass any shim by
   locating and using it directly.

The goal is to eliminate both: the agent sees only opaque placeholder tokens,
and vault credentials never enter the sandbox.

## Solution Overview

**Vault CLIs run out-of-sandbox, proxied through the firma-run broker.** A thin
binary (`firma-secret-shim`) is injected into the sandbox in place of each
configured vault CLI. When the agent spawns one, the shim forwards the request
over a newline-framed JSON socket to a broker server in the firma-run host
process. The broker
holds the vault credentials (read from the host environment at startup), executes
the real CLI out-of-sandbox, extracts the secret(s), and returns placeholder
tokens to the shim. The agent only ever sees placeholders.

For actions that _consume_ secrets (e.g. a GitHub API call carrying an auth
token, or a browser form submission triggered by Playwright), a second mode —
**redact** — is handled by the Sidecar on its existing MITM path. Any outbound
HTTP call from the sandbox that contains a `firma-secret://` placeholder has it
rehydrated before forwarding; any inbound response that reflects a known secret
value has it masked back to a placeholder. No shim is needed for this mode.

Two modes, two mechanisms:

- **intercept** — a shim catches the agent's vault CLI invocation, forwards it
  to the broker out-of-sandbox, which runs the real CLI with host-held
  credentials, extracts secret(s), stores `placeholder → value`, and returns
  placeholder-substituted output to the agent.
- **redact** — the Sidecar scans every outbound HTTP request from the sandbox
  for `firma-secret://` placeholders, rehydrates them from the `SecretStore`,
  and masks known secret values in the corresponding responses. Any outbound call
  is eligible; Cedar policy selects which hosts and paths receive rewrite
  treatment.

Which executables are shimmed (intercept) is per-profile `firma.toml`
configuration. Which outbound HTTP destinations receive redact treatment is
declared in Cedar policy.

## Architecture

```
── intercept path ──────────────────────────────────────────────
                       sandbox boundary
agent ── spawns ──▶  shim  (no secrets, no credentials)
                       │  JSON-line over UDS/TCP (FIRMA_BROKER_ADDR)
                       ▼
              ┌─────────────────────────────────┐
              │  firma-run broker (out-of-sandbox)│
              │  • IntegrationRegistry            │
              │  • SecretStore (write)            │
              │  • execs vault CLI with creds     │
              └──────────────┬──────────────────-┘
                             │  placeholder → value
                             ▼
── redact path ─────────────────────────────────────────────────
  any sandbox process (agent, browser, …)
       │  outbound HTTPS (to external service)
       ▼
  ┌─────────────────────────────────────────────────────────┐
  │  Sidecar (Cedar PDP + MITM proxy)                         │
  │  • secret.redact Cedar eval                               │
  │  • resolves placeholders via JSON-line gateway RPC        │
  │    (FIRMA_SECRET_GATEWAY_ADDR → firma-run)                │
  │  • rehydrate placeholders in reqs                         │
  │  • mask secrets in resps                                  │
  └────────────────────────────────────────────────────────-┘
                   │
                   ▼  external service
```

Three components:

1. **Broker** — embedded in the firma-run host process. Owns the `SecretStore`
   and the `IntegrationRegistry` (built-in CLI specs). Acts as the intercept
   PEP: per shim launch it asks the Sidecar for a `SecretDecision`, executes the
   real vault CLI out-of-sandbox with host-held credentials, and writes
   `placeholder → value` into the `SecretStore`. The broker does not handle
   redact; that responsibility belongs to the Sidecar.

2. **Shim** (`firma-secret-shim`) — a thin cross-platform binary injected into
   the sandbox in place of each configured vault CLI (intercept mode only).
   Forwards the launch request to the broker over a newline-framed JSON socket
   and proxies back the placeholder-substituted output. Holds no secrets and no
   vault credentials. Not used for redact mode.

3. **Sidecar (Cedar PDP + MITM proxy)** — evaluates `secret.mediate` Cedar
   policies (for intercept) and `secret.redact` policies (for redact). On the
   redact path it adds two rewrite passes to its existing MITM pipeline: it
   replaces `firma-secret://` placeholders in outbound request bodies/headers
   with real values from the `SecretStore`, and masks known secret values in
   inbound response bodies back to their placeholders. "Outbound" means any HTTP
   call from any sandbox process to an external host — agent calls, browser form
   submissions, SDK calls, etc. Intra-sandbox traffic (e.g. agent ↔ locally
   spawned MCP server) is invisible to the Sidecar and is not rewritten.

### Shim-to-broker transport

Two sockets are created per session, both in the sandbox's runtime directory
(`<runtime_dir>/secret-shims/`):

- **`broker.sock`** — shim → broker. Carries intercept requests (tool launch
  argv) and returns placeholder-substituted stdout.
- **`gateway.sock`** — Sidecar → broker. Carries batch placeholder-resolution
  requests for the redact path.

Their addresses are injected into the relevant processes as environment
variables:

| Env var                     | Consumer | Format        | Transport                             |
| --------------------------- | -------- | ------------- | ------------------------------------- |
| `FIRMA_BROKER_ADDR`         | shim     | `unix:<path>` | UDS bind-mounted into the sandbox     |
| `FIRMA_BROKER_ADDR`         | shim     | `tcp:<addr>`  | TCP loopback (Windows / non-bwrap)    |
| `FIRMA_SECRET_GATEWAY_ADDR` | Sidecar  | `unix:<path>` | UDS (out-of-sandbox, host filesystem) |
| `FIRMA_SECRET_GATEWAY_ADDR` | Sidecar  | `tcp:<addr>`  | TCP loopback (Windows / non-bwrap)    |

The broker and gateway socket paths are placed in the session runtime directory
at startup (e.g. `<runtime_dir>/secret-shims/broker.sock`), not at a fixed
system path.

On Linux bwrap, the sandbox's network namespace (`--unshare-net`) isolates the
host loopback, so TCP to the host is unreachable. A UDS path bind-mounted into
the sandbox is the right primitive: it lives in the filesystem namespace, not the
network namespace. The egress guard classifies `AF_UNIX` connects separately from
`AF_INET`; the broker socket path can be explicitly allowed without opening a TCP
port.

The shim is platform-aware by design — each backend already requires different
sandbox machinery — so the per-scheme dispatch in the shim adds no hidden
complexity. An intermediate TCP bridge process would add a failure mode and an
extra egress-guard whitelist entry for no benefit.

#### Shim ↔ broker wire protocol

One newline-framed JSON round-trip per connection:

```text
shim  →  {"bin":"bws","args":"secret get <uuid>"}\n
broker → {"stdout":"<base64-encoded stdout>"}\n   (success)
broker → {"error":"<reason>"}\n                   (failure — shim exits non-zero)
```

`args` is the space-joined argument string (everything after the binary name).

#### Sidecar ↔ broker gateway protocol

One newline-framed JSON round-trip per connection. The request carries a batch
of placeholder tokens and the request's target domain; the response is a
positionally-aligned array — one element per placeholder:

```text
→ {"placeholders":["firma-secret://bw/token","firma-secret://bw/other"],"domain":"api.github.com"}\n
← [{"secret_b64":"<base64>"},{"error":"unknown placeholder: ..."}]\n
```

Protocol-level errors (malformed request, oversized request) are returned as a
single error object `{"error":"..."}` so they can be distinguished from an empty
batch. Domain-scoped secrets that do not match `domain` are returned as errors
(same as unknown placeholder — fail closed).

### Why vault CLI exec stays in the broker, not the Sidecar

The Sidecar is a Cedar PDP and network proxy. Giving it exec capability (to run
vault CLIs out-of-sandbox) would couple unrelated responsibilities. The Sidecar
does own the redact path because that is purely HTTP-layer rewriting — a natural
extension of its existing MITM role, requiring no subprocess management.
firma-run is the session orchestrator and the right home for credential storage
and out-of-sandbox exec.

### SecretStore coordination

The `SecretStore` lives in the broker. The broker writes `placeholder → value`
entries after each successful vault CLI intercept. On the redact path the
Sidecar issues a batch lookup request to the broker's gateway socket
(`FIRMA_SECRET_GATEWAY_ADDR`) to resolve each placeholder — see the gateway
protocol above. The broker never pushes entries to the Sidecar.

### Why bind-over-path, not PATH shadowing

PATH shadowing misses absolute-path invocations (`/usr/bin/bws`), renamed
copies, and symlinks. The shim is mounted directly over the real binary path
inside the sandbox (`--ro-bind shim /usr/bin/bws`) so every invocation — however
the binary is reached — hits the shim.

## Vault Credentials Out-of-Sandbox

At sandbox startup, firma-run:

1. Reads each active integration's credential env vars from the **host**
   environment.
2. Stores them in the broker (not logged; zeroized at session end).
3. **Strips them from the sandbox environment** before launching it.

The agent cannot read or exfiltrate the credential because it is never present
in the sandbox. The shim holds no credential — it only forwards the tool launch
request (binary name + args) to the broker. The
broker executes the real vault CLI out-of-sandbox with the credential, captures
its stdout, and applies the integration's extractor.

## Built-in Integrations

Secrets managers fall into two data models, each requiring a different extraction
strategy.

### Simple key-value stores

Each CLI call returns one or more flat `(name, value)` pairs. Placeholder format:
`firma-secret://<provider>/<name>`.

| Integration       | CLI       | Credential env vars                            | Output format / extractor                           |
| ----------------- | --------- | ---------------------------------------------- | --------------------------------------------------- |
| `bitwarden`       | `bws`     | `BWS_ACCESS_TOKEN`                             | JSON array of `{key, value}` objects                |
| `doppler`         | `doppler` | `DOPPLER_TOKEN`                                | `NAME=VALUE` env format (forced via `--format env`) |
| `hashicorp-vault` | `vault`   | `VAULT_TOKEN`, `VAULT_ADDR`, `VAULT_NAMESPACE` | columnar table; regex extracts data rows            |

### Structured-item stores

Each item (identified by name or UUID) contains multiple typed fields — username,
password, TOTP code, card number, URL, and so on. Placeholder format:
`firma-secret://<provider>/<item>/<field>`, where `<item>` is the item title and
`<field>` is the field label, both percent-encoded.

| Integration | CLI  | Credential env vars        | Sensitive field types extracted           |
| ----------- | ---- | -------------------------- | ----------------------------------------- |
| `1password` | `op` | `OP_SERVICE_ACCOUNT_TOKEN` | `CONCEALED`, `TOTP`, `CREDIT_CARD_NUMBER` |

For structured-item integrations, field-type filtering is coded into the
integration's built-in extractor, not expressed in Cedar annotations. When the
broker runs `op item get "GitHub" --format json` it:

1. Parses the JSON response.
2. Reads `$.title` as the item name (`GitHub`).
3. Iterates `$.fields[]`, selecting entries whose `type` is in the sensitive set
   (`CONCEALED`, `TOTP`, `CREDIT_CARD_NUMBER`).
4. For each selected field, mints
   `firma-secret://1password/<title>/<field-label>` and stores
   `placeholder → field value` in the `SecretStore`.
5. Returns the full JSON response with all sensitive field values replaced by
   their placeholders.

Non-sensitive fields (`URL`, `STRING` username, notes) pass through unchanged —
they are not secret and do not need to be tracked.

### Plugin system (future)

A future phase will expose a plugin interface (exact mechanism TBD —
configuration-file schema, WASM, or native) allowing custom integrations with
the same fields: binary name(s), credential env vars, extractor logic,
placeholder template. Built-in integrations serve as the reference
implementation of this interface.

## Placeholder Format

Simple KV:

```
firma-secret://<provider>/<name>
```

Structured item:

```
firma-secret://<provider>/<item>/<field>
```

In both forms every segment is percent-encoded to `[A-Za-z0-9._-]` at mint
time; the only unescaped `/` characters are the segment boundaries. The full
token is the dictionary key; the broker never needs to parse segments back out
at rewrite time.

Properties:

- ASCII, shell- and JSON-safe, and stable through an LLM round-trip.
- Legible: the agent and operators can see which item and field a token refers
  to.
- Fail-closed: an unknown or mangled token yields no dictionary hit, so the
  literal passes through and the tool receives no secret — never a leak.

## Policy and Configuration Model

All behavioral configuration lives in `firma.toml`. Cedar is a pure
authorization layer — permit or forbid per principal, action, and resource — with
no behavioral annotations. Two action classes cover the two modes:

- `Firma::Action::"secret.mediate"` — per shim launch (intercept). The resource
  carries two fields: `resource.bin` (the executable name, e.g. `"bws"`) and
  `resource.args` (the arguments as a space-joined string, e.g.
  `"secret get <uuid>"`). The broker (PEP) consults the Sidecar (PDP) per launch
  over the existing local-exec governance channel.
- `Firma::Action::"secret.redact"` — per outbound HTTP connection (redact);
  evaluated by the Sidecar inline on its MITM path. `resource` is the outbound
  HTTP request (host, port, path).

### `firma.toml` configuration

**Built-in integrations** are activated by name in `secrets_managers`. The
`IntegrationRegistry` spec provides the binary name, credential env vars, and
extractor — no further configuration needed:

```toml
[run.defaults]
secrets_managers = ["bitwarden", "1password"]
```

**Shim names are executable names.** The section key under `[run.shims]` is the
exact binary name that gets bind-mounted in the sandbox (corresponds to
`resource.bin` in Cedar). The optional `match` field restricts interception to a
specific args pattern (corresponds to `resource.args`); without it, any
invocation of that executable is intercepted:

```toml
[run.shims.bws]
# no match field: intercepts all `bws` invocations
integration = "bitwarden"

[run.shims.op]
match = "item get *" # only `op item get …`; other op subcommands pass through
integration = "1password"
```

**Explicit extractors** (custom CLIs or future plugins) require `match` and full
extractor configuration, since nothing is predefined:

```toml
[run.shims.my-vault]
match = "get *"
matcher = "json"
match_value = "$[*].value"
match_name = "$[*].key"
placeholder = "firma-secret://custom/{name}"
```

### Cedar policies

Cedar authorizes which principals and resources may use each configured shim.
Every `secret.mediate` permit rule must correspond to a shim configured in
`firma.toml`; a bundle referencing an unconfigured executable is rejected at
load time.

```cedar
permit(principal, action == Firma::Action::"secret.mediate", resource)
when { resource.bin == "bws" };

permit(principal, action == Firma::Action::"secret.mediate", resource)
when { resource.bin == "op" && resource.args like "item get *" };

permit(principal, action == Firma::Action::"secret.redact", resource)
when { resource.host == "api.github.com" };
```

### Decision semantics (fail-closed)

- Broker cannot reach the Sidecar → **deny** (intercept).
- Sidecar: no matching `secret.mediate` policy → **passthrough** (run the tool untouched).
- Sidecar: no matching `secret.redact` policy → **passthrough** (forward HTTP unchanged).
- Sidecar: `forbid` → **deny**.
- `secret.mediate` policy has a `resource.bin` value not matching any configured shim → **reject bundle at load**.
- Unknown `integration` name in `firma.toml` → **startup error**.

## Intercept Mode: End-to-End Flow

```
agent: executes `bws secret get <uuid>`   (hits shim — real binary is out-of-sandbox)
  │
  ▼  JSON-line to FIRMA_BROKER_ADDR:  {"bin":"bws","args":"secret get <uuid>"}\n
broker:
  1. asks Sidecar → SecretPepOutcome::Permit (via local-exec governance channel)
  2. looks up bitwarden spec: BWS_ACCESS_TOKEN (from host env), JSON extractor
  3. execs `bws secret get <uuid>` out-of-sandbox with BWS_ACCESS_TOKEN
  4. captures stdout; applies built-in extractor
  5. mints placeholder(s): firma-secret://bitwarden/<name>
  6. inserts placeholder → secret into SecretStore
  7. returns {"stdout":"<base64-encoded rewritten output>"}\n → shim → agent
  │
agent: receives `firma-secret://bitwarden/<name>` — never held the real value
```

The credential is never in the sandbox. A new vault CLI is a new
`[run.shims.<name>]` entry in `firma.toml` plus a `secret.mediate` Cedar permit.

## Redact Mode: End-to-End Flow

```
sandbox process ──outbound HTTPS──▶ Sidecar (MITM) ──▶ external service
                [placeholder in req]   [real value]
                                    ◀── [secret in resp masked] ──
```

The Sidecar already terminates TLS for every outbound HTTP call leaving the
sandbox. On the redact path it adds two rewrite passes to that existing
pipeline:

1. **Outbound**: before forwarding the request, scan headers and body for
   `firma-secret://` tokens and substitute each with its real value from the
   `SecretStore`. An unknown placeholder fails closed — the literal passes
   through unchanged, so the external service receives no secret.
2. **Inbound**: before returning the response, scan for known secret values and
   substitute each with its placeholder.

No shim, no broker proxy subprocess, no new listener.

### Example: agent calling GitHub API

The agent wants to list repositories using a token it fetched earlier via `bws`:

```
agent: GET https://api.github.com/user/repos
       Authorization: Bearer firma-secret://bitwarden/github-token
         │  outbound HTTPS via Sidecar
         ▼
Sidecar:
  • secret.redact policy matches api.github.com
  • looks up firma-secret://bitwarden/github-token in SecretStore
  • rewrites Authorization header: Bearer ghp_<real_token>
  • forwards request to GitHub
         │
GitHub:  responds with repository list (may echo token in error messages)
         │
Sidecar: scans response body; masks any occurrence of ghp_<real_token>
         back to firma-secret://bitwarden/github-token
         │
agent:   receives response — never held the real token
```

### Example: Playwright browser form submission

The agent instructs Playwright to fill a password field with a placeholder. The
placeholder travels through the local agent↔Playwright channel (intra-sandbox,
invisible to the Sidecar), Playwright fills it literally into the browser form,
and the browser submits the form as an outbound HTTPS POST. At that point the
Sidecar intercepts the submission, finds the placeholder in the POST body,
rehydrates it with the real password, and forwards the request to the site.

```
agent ──(local stdio/HTTP)──▶ Playwright: browser_fill("password", "firma-secret://…")
                                 │  Playwright drives browser to fill literal placeholder
                                 ▼
browser: POST https://github.com/session  { password: "firma-secret://…" }
                 │  outbound HTTPS via Sidecar
                 ▼
Sidecar: rehydrates placeholder → real password; forwards to github.com
```

Domain binding (see [Domain Binding](#domain-binding)) is enforced here: the
Sidecar checks the request's Host header against the `allowed_domain` on the
`SecretStore` entry. If they do not match, the placeholder is left unrewritten
and the site receives the literal token — fail closed.

## Transforms

The Sidecar selects the substitution codec per-request, never per-policy. A
single `secret.redact` rule can match JSON API calls, HTML form submissions, and
XML payloads to the same host — the codec must be chosen at request time, not
at policy authoring time.

### Finding placeholders

Placeholder search is always a literal UTF-8 byte scan — the placeholder format
(`firma-secret://provider/name`) is URI-safe ASCII and appears identically in
every serialization (JSON string, form value, XML element, header value).
Overlap buffers (`maxPlaceholderLen - 1`) handle tokens split across chunk
boundaries in streaming bodies.

### Encoding the secret value (outbound rehydration)

Once the placeholder is located, the replacement must be encoded to fit the
surrounding syntax. The Sidecar uses the following detection order:

**1. `Content-Type` request header** (primary — reliable for well-formed clients)

| Content-Type                                       | Encoding applied to secret value                      |
| -------------------------------------------------- | ----------------------------------------------------- |
| `application/json`                                 | JSON string escaping: `"`, `\`, control characters    |
| `application/x-www-form-urlencoded`                | percent-encoding (RFC 3986 unreserved chars left raw) |
| `application/xml`, `text/xml`, `application/*+xml` | XML character escaping: `&`, `<`, `>`, `"`            |
| `text/plain`                                       | raw bytes                                             |
| Headers (Authorization, Cookie, etc.)              | raw bytes                                             |

**2. Body sniffing** (fallback when `Content-Type` is absent or
`application/octet-stream`)

Inspect the first non-whitespace bytes of the body:

- Starts with `{` or `[` → treat as JSON
- Starts with `<` → treat as XML
- Matches `key=value` pattern (`=` present, no `{` or `<`) → treat as
  form-encoded
- Otherwise → raw

**3. Raw** (last resort)

If sniffing is inconclusive, substitute the secret bytes without encoding. The
placeholder is always findable (it is ASCII), and raw substitution is an
operational risk (a secret containing `"` in a JSON body will corrupt it), not a
security risk — the malformed request errors at the external service, nothing is
leaked, fail-closed is preserved. A warning is logged.

### Masking secrets (inbound response)

On the response path the Sidecar applies the same detection order against the
response `Content-Type`. Additionally, because the external service may reflect
the secret in a different encoding than it was received, the Sidecar generates
all encoded forms of each known secret value — raw, JSON-escaped,
percent-encoded, and XML-escaped — and runs a single multi-pattern Aho-Corasick
scan over the body. Any match in any form is replaced with the literal
placeholder token.

## Secret Lifecycle

The `SecretStore` is populated **only by intercept** — only when the agent calls
a vault CLI. Redact rehydrates a placeholder only if it is already in the store;
an unknown placeholder on stdin **fails closed** (the literal is not substituted,
so the tool receives no secret). The broker never contacts the vault itself; it
only executes the vault CLI per-request. Consequence: the agent must fetch a
secret via the vault CLI before it can use the corresponding placeholder in a
redact target.

The store is run-scoped and zeroized on teardown.

## Domain Binding

**Motivation**: a placeholder like `firma-secret://1password/GitHub/password`
should only be rehydrated in requests destined for `github.com`. Rehydrating on
any outbound request would let the agent exfiltrate the real value by sending
the placeholder to an attacker-controlled host. This is the same control browser
password managers apply: credentials only autofill on the domain they belong to.

Because the Sidecar intercepts outbound HTTP calls, the destination domain is
always known from the request's `Host` header — no state tracking is required.

### Source of domain data

For 1Password structured items, the item JSON already includes a `URL` field
(type `URL`, non-sensitive — currently not extracted). The 1Password extractor
reads this field during item parsing and associates the extracted hostname with
every sensitive field minted from that item:

```
firma-secret://1password/GitHub/password  →  { value: "...", allowed_domain: "github.com" }
```

For flat key-value integrations (Bitwarden, Doppler, HashiCorp Vault) the
secret response carries no domain metadata. Domain binding for those
integrations can only be configured explicitly via Cedar annotations or
`firma.toml`; absent such configuration, rehydration is unconditional.

### Enforcement

The Sidecar enforces domain binding per-request in the rehydration step:

1. Resolve the placeholder to its `SecretStore` entry.
2. If the entry has an `allowed_domain`, compare it against the `Host` header of
   the outbound request (e.g. `github.com` from `Host: github.com`).
3. **Match** → rehydrate.
4. **No match** → fail closed: leave the literal placeholder unchanged; log the
   domain mismatch. The external service receives the literal token, not a secret.
5. **No `allowed_domain` on the entry** → rehydrate unconditionally
   (backwards-compatible default; operators opt in to binding by using a
   1Password item with a URL field or by adding an explicit configuration).

### Threat model addition

Domain binding constrains an agent that passes a placeholder to a non-matching
external host. It does not prevent an agent from sending a request to the target
domain and using the placeholder there — that is the intended behavior. The
remaining residual: the agent can call the target domain, route the credential,
and observe the outcome (e.g., a successful login). Cedar `forbid` rules can
close this if the operator does not want the agent to authenticate to that site
at all.

## Configuration

```toml
[run.defaults]
# Activates built-in integrations: drives credential stripping and shim
# injection for vault CLI binaries (intercept mode only).
secrets_managers = ["bitwarden", "1password"]

[run.profiles.playwright-agent]
secrets_managers = ["bitwarden", "1password"]
```

Redact behavior (which HTTP endpoints the Sidecar rewrites) is declared in
Cedar policy rather than `firma.toml`, because it operates on outbound HTTP
connections that the Sidecar already governs — no startup-time credential
stripping or shim injection is required.

```cedar
permit(principal, action == Firma::Action::"secret.redact", resource)
when { resource.host == "api.github.com" };
```

## Threat Model

- **Broker is the trust anchor.** The `SecretStore` and vault credentials live in
  the firma-run broker, out-of-sandbox. Values are `Zeroizing<Vec<u8>>`; the
  store is run-scoped.
- **Vault credentials out-of-sandbox.** Credentials are stripped from the
  sandbox before it starts. An agent that bypasses the shim has no credential to
  present to the vault.
- **Residual redact exposure.** A sanctioned tool `T` receives real plaintext in
  the rehydrated HTTP request body (unavoidable; it must function). An agent
  could `ptrace` that specific `T` to observe a secret it itself chose to route
  there — but it cannot enumerate the store or read other secrets.
- **Masking is best-effort.** Secrets transformed before output (base64, hex,
  chunked) will not match the literal masker. The primary control is that the
  agent never holds the plaintext; stdout masking is defense-in-depth.

## Phased Plan

| Phase | Scope                                                                                                                                                                                                                                       | Crates                                       | Outcome                                             |
| ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------- | --------------------------------------------------- |
| 0     | This design doc                                                                                                                                                                                                                             | docs                                         | Reviewed                                            |
| 1     | `SecretStore`, `Placeholder`, `SecretValue`, Aho-Corasick matcher                                                                                                                                                                           | `firma-run`                                  | Unit tests: dictionary, masking                     |
| 2     | Cedar: `secret.mediate` / `secret.redact` action schemas; `SecretMediation` enum; load-time bundle validation (shim cross-check)                                                                                                            | `firma-core`, `firma-sidecar`                | Unit tests: bundle parse/validate, shim cross-check |
| 3     | `IntegrationRegistry`: built-in specs for `bitwarden`, `1password` (structured-item extractor), `hashicorp-vault`, `doppler`; credential env var stripping                                                                                  | `firma-run`, `firma-config-loader`           | Integration tests with fake CLIs                    |
| 4     | firma-run JSON-line broker + gateway sockets; shim binary; intercept mode end-to-end with out-of-sandbox vault CLI exec; bind-over-path shim injection                                                                                      | `firma-run`                                  | E2E on bwrap with mock vault CLIs                   |
| 5     | Content-Type–driven rewriter in Sidecar MITM path (`raw`, `json`, `form`, `xml`); multi-pattern Aho-Corasick masking; `secret.redact` Cedar eval; SecretStore read path in Sidecar; Host-header domain binding; docs (docs-site + llms.txt) | `firma-sidecar`, `firma-config-loader`, docs | `just check` green                                  |
| 6     | Streaming rewrite with overlap buffers for chunked and HTTP/2 responses                                                                                                                                                                     | `firma-sidecar`                              | Property tests on chunk splits                      |
| 7     | Plugin interface for custom integrations; additional backends (macOS vz, WSL2)                                                                                                                                                              | `firma-run`, backends                        | —                                                   |

## Resolved Design Decisions

### Behavior configuration: `firma.toml`

All shim behavioral config (which integrations are active, which executables are
shimmed, explicit extractor specs) lives in `firma.toml`. Cedar is
authorization-only — no behavioral annotations. This keeps `firma.toml` the
single operational config file, avoids a timing dependency between Cedar bundle
fetch and sandbox startup, and keeps Cedar readable by operators without knowing
extractor internals.

### Integration implementation: CLI wrappers

The broker shells out to the already-installed vault CLI with host-held
credentials and parses its stdout. The CLI must be present on the host; this is
a safe assumption since the agent's workflow depends on it regardless of whether
firma is involved. API changes are absorbed by the CLI; firma never touches the
wire protocol.

Native Rust clients are reserved for network-only secret services (AWS, GCP,
Azure) that have no local CLI — see [Future Development](#future-development-network-only-secret-services).

### SecretStore location: broker (firma-run)

The `SecretStore` lives in the broker. The Sidecar resolves placeholders on
demand by sending a batch request to the gateway socket (`FIRMA_SECRET_GATEWAY_ADDR`).
This preserves the existing Sidecar security boundary — a Sidecar compromise
does not yield the secret dictionary. The IPC round-trip on the redact hot path
is acceptable; a short-lived local cache of recently resolved entries can be
added if it becomes a measurable bottleneck.

## Future Development: Network-Only Secret Services

Some secrets managers expose no local CLI with local decryption — the secret
travels over HTTPS and arrives as a plaintext value in the API response body.
Examples: AWS Secrets Manager, Google Cloud Secret Manager, Azure Key Vault.
Agents access these through cloud SDKs (Python `boto3`, the GCP or Azure client
libraries) or via the respective cloud CLI (`aws secretsmanager get-secret-value`,
`gcloud secrets versions access`), both of which make authenticated HTTPS calls
and receive the plaintext in the response.

The CLI shim approach does not apply here: there is no subprocess whose stdout
contains a locally-decrypted secret. The natural interception point is the
**HTTPS response body** — which the Sidecar already sits on.

This is the same MITM infrastructure used for redact. The difference is
directionality: redact rewrites _outbound_ request bodies (agent → tool) and
masks _inbound_ response bodies (tool → agent); network intercept rewrites
_inbound_ response bodies (secret service → agent) and writes to the
`SecretStore`. A Cedar `secret.capture` action would cover this.

```
agent: boto3.get_secret_value(SecretId="prod/db/password")
  │  HTTPS (via Sidecar MITM)
  ▼
AWS Secrets Manager API  →  { "SecretString": "hunter2" }
  │  response intercepted by Sidecar
  ▼
Sidecar:
  • Cedar policy permits secret.capture for this host + path
  • extracts "SecretString" field value
  • mints firma-secret://aws/<secret-id>
  • writes placeholder → "hunter2" into SecretStore (via broker RPC)
  • rewrites response: { "SecretString": "firma-secret://aws/prod%2Fdb%2Fpassword" }
  │
agent: receives placeholder — never held the real value
```

### Differences from CLI intercept

| Dimension                 | CLI intercept (this design)              | Network intercept (future)                                        |
| ------------------------- | ---------------------------------------- | ----------------------------------------------------------------- |
| Interception point        | Broker: vault CLI stdout                 | Sidecar: HTTPS response body                                      |
| Credential location       | Stripped from sandbox; broker holds them | Cloud credentials remain in sandbox (agent authenticates itself)  |
| Who writes to SecretStore | Broker                                   | Sidecar (via broker RPC or directly, depending on store location) |
| Infrastructure required   | Shim binary + broker HTTP server         | HTTPS MITM (already exists)                                       |

The credential-stripping invariant is weaker for network intercept: the agent
must hold cloud credentials to authenticate the API call, so those credentials
remain in the sandbox. An agent could make additional unauthorized calls to the
cloud service — the Sidecar's existing egress policy (action class matching on
host + method + path) is the control, not credential absence.

## Follow-ups

- Additional vault CLIs (`bw`, `aws secretsmanager`, `gcloud secrets versions
  access`) are new `IntegrationRegistry` entries — no architectural change.
- Intra-sandbox traffic (agent ↔ locally spawned MCP server, stdio or loopback)
  does not traverse the Sidecar; redact is not available on that path. Secrets
  passed locally must be rehydrated by the agent itself or by the tool receiving
  them — neither of which firma controls. This is a known gap tracked in
  `docs/security/bypass-risks.md`. The Playwright browser form-submission path
  is covered because the browser's outbound HTTP exits the sandbox through the
  Sidecar.
- Whether `secret.mediate` and `secret.redact` should further split into
  `secret.resolve` / `secret.inject` verbs — deferred.
- Plugin interface mechanism (config-file schema, WASM, native library) —
  deferred to phase 7.
