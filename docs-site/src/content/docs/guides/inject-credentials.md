---
title: Inject credentials
description: Attach upstream credentials at the Sidecar instead of letting agents hold them.
---

A capability proves an agent is *authorized* to make a call. A **credential** is what the upstream service itself wants to see — an `Authorization: Bearer …` header, an API key in a query string, an mTLS client cert. OpenFirma can attach these at the Sidecar after a request is allowed, so the agent process never holds the secret.

This is one of the highest-value reasons to deploy a Sidecar at all: a compromised agent that never touches the credential cannot exfiltrate it.

You should already have a Sidecar running with HTTPS MITM enabled for the relevant hosts ([Enable HTTPS MITM](../https-mitm/)). MITM is required because credential injection happens at L7 — the Sidecar must be able to decrypt and modify the request. `firma config --mapping anthropic` (or `openai`) scaffolds CONNECT mappings with **empty** `intercept_hosts` by default — add `api.anthropic.com` / `api.openai.com` to `[sidecar.interceptor.https_mitm].intercept_hosts` before expecting injection to work.

## Step 1: Decide what you're injecting and where

Three pieces of information per credential:

1. **Which host** the credential is for. Injection is host-scoped to prevent cross-host leakage.
2. **Which header** the upstream expects. Most often `Authorization`, sometimes a custom header.
3. **Where the secret lives** at the Sidecar host. Two modes today: a host environment variable (`basic` mode) or a file rendered by Vault Agent (`vault` mode).

A typical setup for OpenAI:

```text
host:           api.openai.com
header:         Authorization
prefix:         Bearer<space>
value source:   $OPENAI_API_KEY
```

## Step 2: Configure with `basic` mode (env-var-backed)

Add keyed `[sidecar.credentials.<label>]` tables to `firma.toml`:

```toml
[sidecar.credentials.openai]
target_host    = "api.openai.com"
mode           = "basic"
header         = "Authorization"
value_from_env = "OPENAI_API_KEY"
prefix         = "Bearer "

[sidecar.credentials.anthropic]
target_host    = "api.anthropic.com"
mode           = "basic"
header         = "x-api-key"
value_from_env = "ANTHROPIC_API_KEY"
```

Field-by-field:

- **`target_host`** — exact match. Wildcards aren't supported here; if you need cross-subdomain injection, list each host.
- **`mode`** — `"basic"` reads from an env var. `"vault"` covered below.
- **`header`** — name of the HTTP header to attach.
- **`value_from_env`** — the name of the environment variable on the Sidecar host that holds the secret. The Sidecar reads it once at startup and keeps it in memory.
- **`prefix`** — optional string prepended to the env var value. The space at the end of `"Bearer "` matters.

Set the env var when launching the Sidecar:

```bash
OPENAI_API_KEY=sk-... \
ANTHROPIC_API_KEY=sk-ant-... \
firma sidecar -c firma.toml
```

Restart, then check that injection happens. With MITM enabled for these hosts, you should be able to make calls from the agent without setting any local API key:

```bash
curl --proxy http://127.0.0.1:8080 \
  https://api.openai.com/v1/models
# -> 200 OK
# Even though we never set Authorization on the curl
```

The Sidecar attached `Authorization: Bearer sk-...` after Stage 2 allowed the call.

## Step 3: Inject a GitHub token for HTTPS git

GitHub smart HTTP expects a Basic auth header for git clone, fetch, and push. Use `transform = "github_pat_basic"` to render a token as:

```text
Authorization: Basic base64("x-access-token:<token>")
```

```toml
[sidecar.credentials.github_git]
target_host    = "github.com"
mode           = "basic"
header         = "Authorization"
value_from_env = "GITHUB_TOKEN"
transform      = "github_pat_basic"
```

Keep this scoped to `target_host = "github.com"`. Credential matching is exact, so this git credential is not applied to `api.github.com`. Git credential injection also requires HTTPS MITM for `github.com`; if the Sidecar only sees a CONNECT tunnel, it cannot attach the header to the inner request.

## Step 4: Configure with `vault` mode

For production, env vars on the Sidecar host are still secrets-on-disk that an attacker with shell could read. `vault` mode reads the secret from a local file that Vault Agent renders and refreshes.

```toml
[sidecar.credentials.openai]
target_host = "api.openai.com"
mode        = "vault"
header      = "Authorization"
prefix      = "Bearer "
secret_path = "/run/secrets/openai-api-key"
```

`transform = "github_pat_basic"` is also supported in `vault` mode. Do not combine `prefix` and `transform` on the same credential entry.

Configure Vault Agent separately to render the secret value into `/run/secrets/openai-api-key` with permissions readable only by the Sidecar process.

The Sidecar reads the file per call. If the file is missing or unreadable when a request comes in, the Sidecar returns `CREDENTIAL_INJECTION_FAILED` and aborts the already-allowed call — fail-closed by design. The agent receives a `504` with `"aborted": true`; the capability token remains active.

For the development workflow, `basic` is simpler. For production, `vault` is the answer. Don't mix them in a single deployment unless you have a clear reason.

## Step 5: Verify injection

The audit event records the allowed dispatch, but not whether a credential was injected and never the credential value:

```json
{
  "action": "communication.external.send",
  "resource": "api.openai.com/v1/chat/completions",
  "decision": 1,
  "deny_reason": "",
  "dispatch_status": 200
}
```

If the upstream returns `401` for a host you expected injection on, you have a misconfiguration — usually `target_host` exact-match mismatch (the request hit `oai.openai.com` and your config has `api.openai.com`) or a missing secret source.

## Where injection sits in the pipeline

Injection happens in the connector, **after** Stage 2 has allowed the call. The order matters:

1. Stage 1 validates the capability — the agent had no credential at that point.
2. Stage 2 evaluates the policy — same.
3. Connector dispatches — and *now* it adds the credential before sending.

This means policies cannot inspect the credential value (good — they shouldn't), and a denied call never sees a credential attached (good — no chance of leaking via error responses). It also means injection cannot influence the policy decision: the agent cannot smuggle "the right answer" into the credential and have the policy see it.

## Why scope per host

Two tempting shortcuts that the design rejects:

**"Inject the same credential on every host."** Bad — a leaked credential to host A becomes a credential to host B, which the upstream might honor or might log in a way that exposes it further. Per-host scoping bounds the blast radius.

**"Inject from the request body."** Bad — that would let the agent control what gets injected, defeating the point of the Sidecar holding the secret. The design only supports static, host-keyed sources.

If you genuinely need different credentials per *call* (e.g. multi-tenant agent that acts on behalf of different end-users), that's a different problem. The right shape is per-tenant capabilities and per-tenant Sidecar instances, not dynamic injection.

## Common gotchas

**`Authorization` already present.** If the agent set the header itself (a curl with `-H 'Authorization: ...'`), the Sidecar's behavior depends on configuration; by default, the Sidecar's value wins. Always assume injection clobbers — if you need pass-through behavior, do not configure injection for that host.

**`OPENAI_API_KEY` not set; injection silently disabled.** Wrong — it's not silent. The Sidecar fails startup with an error pointing at the missing env var. Fail-closed at startup is the right shape.

**MITM is off for the host.** The Sidecar can't modify a request it never decrypted. Add the host to `intercept_hosts` (see [Enable HTTPS MITM](../https-mitm/)).

**GitHub PAT attached to API calls.** Scope git credentials to `github.com`, not `api.github.com`. GitHub REST API credentials should use their own credential entry and policy.

**Vault Agent stopped refreshing the file.** The Sidecar reports `CREDENTIAL_INJECTION_FAILED` for that host until the rendered file is present and readable again.

**Agent gets a `401` from upstream.** The injected key is wrong, expired, or for the wrong account. Check the env var or rendered Vault Agent file.

## Operational checklist

For a production deployment:

- [ ] Every host that requires a credential has a `[sidecar.credentials.<label>]` table.
- [ ] No production host uses `mode = "basic"`. Vault for everything sensitive.
- [ ] The Sidecar process has *only* the env vars it needs — no inherited shell env.
- [ ] The Sidecar host has filesystem permissions tight enough that a shell on it can't read the credentials cache.
- [ ] Rotation strategy: how do you change the upstream key, and how does the Sidecar pick up the new one?
- [ ] Audit log review: do allowed calls to credentialed hosts return the expected upstream status?

## What's next

- [Read & verify the audit log](../audit-log/) — see injection records cleanly.
- [Concepts: Connectors](../../concepts/connectors/) — the dispatch path and where injection fits.
- [Concepts: Threat model](../../concepts/threat-model/) — the security rationale.
