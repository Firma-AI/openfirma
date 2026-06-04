---
title: Enable HTTPS MITM
description: Bootstrap the Sidecar's CA, trust it on the agent host, and pick which hosts to inspect at L7.
---

CONNECT-only HTTPS gives you destination-level policy ("the agent may not contact this host"). HTTPS MITM gives you full L7 policy ("the agent may not POST a payload over this size to this path"). This guide walks you through enabling MITM safely: bootstrap the CA once, trust it narrowly on the agent host, and decide which hosts deserve L7 inspection.

You should already have a Sidecar running ([Run the sidecar standalone](../run-the-sidecar/)).

## Before you start: read the warnings

The MITM CA is the single most security-sensitive artifact in an OpenFirma deployment. Two rules:

1. **Bootstrap the CA once. Never regenerate it.** Once a host trusts your CA, it has to keep trusting it. Regenerating means revisiting trust on every agent host.
2. **Trust the CA on the agent's process, not the OS-wide trust store.** Use `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, or per-language equivalents. Never copy the CA into `/etc/ssl/certs/` system-wide.

For the conceptual background see [Concepts: Interception](../../concepts/interception/).

## Step 1: Bootstrap the CA

Add a `[sidecar.ca]` section to `firma.toml`:

```toml
[sidecar.ca]
dir = "/tmp/firma-standalone/firma-ca"
```

Restart the Sidecar. On first start with no existing CA, it generates one:

```text
INFO firma_sidecar::startup::ca: bootstrapping CA at /tmp/firma-standalone/firma-ca
INFO firma_sidecar::startup::ca: wrote firma-ca.crt and firma-ca.key
INFO firma_sidecar: sidecar ready
```

Inspect the directory:

```bash
ls /tmp/firma-standalone/firma-ca/
# firma-ca.crt   firma-ca.key
```

`firma-ca.crt` is the public certificate (this is what agents trust). `firma-ca.key` is the private key (keep it `chmod 600`). From this point forward, **do not delete or regenerate these files**.

In production, treat the CA directory as immutable infrastructure: provision it once, back it up encrypted, never check it into version control.

## Step 2: Configure MITM hosts

Add a `[sidecar.interceptor.https_mitm]` block to `firma.toml`:

```toml
[sidecar.interceptor.https_mitm]
enabled         = true
intercept_hosts = [
  "api.openai.com",
  "api.anthropic.com",
  "api.stripe.com",
]
bypass_hosts    = []
strict_hosts    = ["api.stripe.com"]
```

What each list does:

- **`intercept_hosts`** — explicit MITM allowlist. Wildcards like `*.anthropic.com` work. Anything in this list gets TLS-terminated; the Sidecar can read method, path, headers, body.
- **`bypass_hosts`** — explicit fallback to CONNECT-only. Use for hosts that pin certificates or otherwise reject MITM. You'll only see destination-level policy on these.
- **`strict_hosts`** — if MITM fails for any reason on these hosts (handshake mismatch, parse error), DENY rather than fall back. Use for hosts where you'd rather break the call than enforce a weaker policy on it.

Hosts not in any list use the configured default behavior — typically CONNECT-only.

`enabled = true` with an empty `intercept_hosts` is treated as MITM **disabled**, not as an error: there is nothing to intercept, so the Sidecar starts and falls back to CONNECT-only tunnels. This is why a freshly scaffolded `firma config` (which emits an empty `intercept_hosts`) starts cleanly under standalone `firma sidecar --config`. To actually intercept, add at least one host.

Restart the Sidecar. The startup log will list how many MITM hosts are configured.

## Step 3: Trust the CA on the agent host

This is the part that varies by agent runtime. The unifying principle: **trust the CA narrowly, on the agent's process or sandbox**, not on the host's global trust store.

### Python (`requests`, `httpx`)

```bash
export REQUESTS_CA_BUNDLE=/tmp/firma-standalone/firma-ca/firma-ca.crt
export SSL_CERT_FILE=/tmp/firma-standalone/firma-ca/firma-ca.crt
```

These environment variables apply only to the process that inherits them. They are by far the simplest narrow-scope trust mechanism.

### Node.js

```bash
export NODE_EXTRA_CA_CERTS=/tmp/firma-standalone/firma-ca/firma-ca.crt
```

### curl

`curl --cacert <path>` per invocation, or:

```bash
export CURL_CA_BUNDLE=/tmp/firma-standalone/firma-ca/firma-ca.crt
```

### Go

Go's `crypto/tls` does not respect a single env var by default. The simplest path is to bundle the CA into your code's `tls.Config.RootCAs`. If you can't change the code, run the agent under `firma run` — the wrapper handles this for supported profiles.

### Inside `firma run`

When you launch with `firma run`, the wrapper installs the CA into the sandbox's trust path automatically and sets the appropriate env vars for the runtime profile. You don't need to do anything else for [`firma run`](../firma-run/)-wrapped agents.

## Step 4: Verify MITM is in effect

With the env vars set in your agent shell, make a verbose HTTPS call:

```bash
curl --proxy http://127.0.0.1:8080 -v https://api.openai.com/v1/models 2>&1 | grep -E "issuer:|subject:"
```

Look for `issuer: CN=Firma…` (or whatever your CA's common name is) on the leaf cert. If you see the real OpenAI cert chain instead, MITM is not active for this host — check `intercept_hosts`.

In the audit log, MITM-intercepted calls show full L7 details:

```json
{
  "envelope": {
    "intent": {
      "action_class": "model.inference.chat",
      "resource": {
        "host": "api.openai.com",
        "path": "/v1/models",
        "provider": null
      }
    }
  }
}
```

CONNECT-only calls show only the host:

```json
{
  "envelope": {
    "intent": {
      "action_class": null,
      "resource": { "host": "api.openai.com:443" }
    }
  }
}
```

If you don't see method, path, and provider on a host you intended to MITM, walk through the configuration step by step.

## Picking what to MITM

A reasonable default policy:

| Host class                                                | MITM?                |
| --------------------------------------------------------- | -------------------- |
| LLM provider APIs (OpenAI, Anthropic, Mistral)            | Yes                  |
| SaaS APIs you have admin access to (Stripe, Slack, GitHub)| Yes                  |
| Your own services / internal SaaS                         | Yes                  |
| Third-party SaaS where MITM violates terms                | No (CONNECT-only)    |
| Banking, healthcare, certificate-pinning APIs             | No (CONNECT-only)    |
| Self-signed internal services                             | No (CONNECT-only)    |

Add to `intercept_hosts` only what you actually want L7 visibility on. Everything else — `bypass_hosts` or untouched (default).

## What about cert pinning?

If an agent uses an SDK that pins certificates (validates the cert chain against a hardcoded fingerprint), MITM will fail with a cert-mismatch error in the agent. Two options:

1. **Add the host to `bypass_hosts`.** You'll get destination-level policy only.
2. **Replace the SDK** with one that doesn't pin. Most LLM and SaaS SDKs do not pin; banking and security SDKs sometimes do.

Don't try to "fix" a pinning error by changing the pin — pinning is a security feature on the agent's side, and the right answer is to respect it (and lose L7 visibility for that host).

## Common gotchas

**`x509: certificate signed by unknown authority`** in the agent. The agent process didn't pick up the CA. Re-export the env var in the *exact* shell that launches the agent, or use `firma run`.

**MITM works for some hosts but not others.** Wildcards in `intercept_hosts` are leading-only (`*.anthropic.com`). They don't match across multiple labels (`*.anthropic.com` does not match `api.dev.anthropic.com`). Add explicit entries.

**Sidecar logs `mitm_handshake_failed`.** The agent's TLS client rejected the cert the Sidecar minted. Usually means the agent doesn't trust your CA — re-check trust setup. If the host is sensitive, add it to `strict_hosts` so the failure denies instead of falling back.

**Audit log shows `decision.outcome=ALLOW` but the agent reports a TLS error.** The Sidecar terminated TLS to the agent fine, then the upstream rejected the Sidecar's outbound TLS connection. Look for `connector_network_error` in the same event.

**You regenerated the CA and now nothing works.** Don't. The fix is to find your old CA in a backup. If you genuinely have to start over, you must re-trust the new CA on every agent host before they can talk again.

## What's next

- [Inject credentials](../inject-credentials/) — now that you can MITM, you can attach upstream credentials at the boundary.
- [Read & verify the audit log](../audit-log/) — see the L7 detail for MITM hosts.
- [Concepts: Threat model](../../concepts/threat-model/) — the security implications of MITM.
