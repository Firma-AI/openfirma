---
title: Inject credentials
description: Attach upstream credentials at the Sidecar instead of letting agents hold them.
---

A capability proves an agent is *authorized* to make a call. A **credential** is what the upstream service itself wants to see — an `Authorization: Bearer …` header, an API key in a query string, an mTLS client cert. OpenFirma can attach these at the Sidecar after a request is allowed, so the agent process never holds the secret.

This is one of the highest-value reasons to deploy a Sidecar at all: a compromised agent that never touches the credential cannot exfiltrate it.

You should already have a Sidecar running with HTTPS MITM enabled for the relevant hosts ([Enable HTTPS MITM](../https-mitm/)). MITM is required because credential injection happens at L7 — the Sidecar must be able to decrypt and modify the request.

## Step 1: Decide what you're injecting and where

Three pieces of information per credential:

1. **Which host** the credential is for. Injection is host-scoped to prevent cross-host leakage.
2. **Which header** the upstream expects. Most often `Authorization`, sometimes a custom header.
3. **Where the secret lives** at the Sidecar host. Two modes today: a host environment variable (`basic` mode) or a Vault path (`vault` mode).

A typical setup for OpenAI:

```text
host:           api.openai.com
header:         Authorization
prefix:         Bearer<space>
value source:   $OPENAI_API_KEY
```

## Step 2: Configure with `basic` mode (env-var-backed)

Add `[[sidecar.credentials]]` blocks to `firma.toml`:

```toml
[[sidecar.credentials]]
host           = "api.openai.com"
mode           = "basic"
header         = "Authorization"
value_from_env = "OPENAI_API_KEY"
prefix         = "Bearer "

[[sidecar.credentials]]
host           = "api.anthropic.com"
mode           = "basic"
header         = "x-api-key"
value_from_env = "ANTHROPIC_API_KEY"
```

Field-by-field:

- **`host`** — exact match. Wildcards aren't supported here; if you need cross-subdomain injection, list each host.
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

## Step 3: Configure with `vault` mode

For production, env vars on the Sidecar host are still secrets-on-disk that an attacker with shell could read. `vault` mode keeps the secret in HashiCorp Vault and the Sidecar fetches it lazily.

```toml
[[sidecar.credentials]]
host        = "api.openai.com"
mode        = "vault"
header      = "Authorization"
prefix      = "Bearer "
secret_path = "secret/data/openai/api-key"
secret_key  = "value"
```

Plus a `[sidecar.credentials.vault]` block for connection details:

```toml
[sidecar.credentials.vault]
addr     = "https://vault.internal:8200"
token    = "<vault-token>"   # or AppRole auth via separate config
namespace = "agents"          # optional, for Vault Enterprise
```

The Sidecar reads `secret/data/openai/api-key` and uses the value of the `value` field. If Vault is unreachable when a request comes in, the connector returns `CredentialUnavailable` and the call denies — fail-closed by design.

For the development workflow, `basic` is simpler. For production, `vault` is the answer. Don't mix them in a single deployment unless you have a clear reason.

## Step 4: Verify injection in the audit log

The audit event records *that* injection happened, but **not the value**:

```json
{
  "envelope": {
    "intent": {
      "action_class": "model.inference.chat",
      "resource": { "host": "api.openai.com", "path": "/v1/chat/completions" }
    }
  },
  "decision": { "outcome": "ALLOW" },
  "connector": {
    "credential_injected": true,
    "credential_source": "basic"
  }
}
```

If `credential_injected` is `false` for a host you expected injection on, you have a misconfiguration — usually `host` exact-match mismatch (the request hit `oai.openai.com` and your config has `api.openai.com`).

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

**Vault token expired.** The Sidecar reports `CredentialUnavailable` for that host until you refresh the token. In production, configure AppRole auto-rotation rather than long-lived tokens.

**Agent gets a `401` from upstream.** The injected key is wrong, expired, or for the wrong account. The audit log shows `credential_injected: true` — the Sidecar attached *something*, but the upstream rejected it. Check the env var or Vault path.

## Operational checklist

For a production deployment:

- [ ] Every host that requires a credential has a `[[sidecar.credentials]]` block.
- [ ] No production host uses `mode = "basic"`. Vault for everything sensitive.
- [ ] The Sidecar process has *only* the env vars it needs — no inherited shell env.
- [ ] The Sidecar host has filesystem permissions tight enough that a shell on it can't read the credentials cache.
- [ ] Rotation strategy: how do you change the upstream key, and how does the Sidecar pick up the new one?
- [ ] Audit log review: are `credential_injected` events what you expect for each host?

## What's next

- [Read & verify the audit log](../audit-log/) — see injection records cleanly.
- [Concepts: Connectors](../../concepts/connectors/) — the dispatch path and where injection fits.
- [Concepts: Threat model](../../concepts/threat-model/) — the security rationale.
