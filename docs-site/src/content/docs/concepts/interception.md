---
title: Interception
description: How the Sidecar captures outbound agent traffic — proxy, gRPC hook, Unix socket, and HTTPS MITM.
---

The Sidecar can only enforce on traffic it sees. **Interception** is how it gets the agent's outbound calls into the [enforcement pipeline](../pipeline/) in the first place. There are several modes, and choosing among them is one of the more impactful decisions when wiring OpenFirma into a real environment.

This page covers the three transport modes, the CONNECT vs MITM trade-off for HTTPS, and the operational consequences of each choice.

## The three transport modes

```text
┌──────────┐    HTTP_PROXY=...     ┌──────────────────┐
│  Agent   │ ────────────────────► │   HTTP proxy     │  default for most workloads
└──────────┘                       └──────────────────┘

┌──────────┐    in-process call    ┌──────────────────┐
│  Agent   │ ────────────────────► │  gRPC interceptor│  programmatic, no port binding
└──────────┘                       └──────────────────┘

┌──────────┐    /run/firma.sock    ┌──────────────────┐
│  Agent   │ ────────────────────► │   Unix socket    │  containers, multi-tenant hosts
└──────────┘                       └──────────────────┘
```

All three feed the same `RawRequest` shape into the pipeline, so the rest of the Sidecar — normalizer, Stage 1, Stage 2, audit — is identical regardless of how the request arrived.

### HTTP proxy

The default. The Sidecar listens on a TCP port (default `127.0.0.1:8080`) and the agent is configured with `HTTP_PROXY` and `HTTPS_PROXY`. Every popular language and HTTP client respects these environment variables, including Python's `requests`, Node's `fetch` and `axios`, Go's `net/http`, Rust's `reqwest`, and most LLM SDKs.

This is the right mode for almost every starting workload. It works without code changes, and you don't have to rebuild the agent to put it behind enforcement.

Configured in `sidecar.toml` as:

```toml
[interceptor]
mode               = "http_proxy"
listen_addr        = "127.0.0.1:8080"
drain_timeout_secs = 5
```

### gRPC interceptor

A programmatic mode for SDKs that integrate the Sidecar in-process. The agent calls the Sidecar's gRPC interceptor service directly instead of going through a proxy. There's no port binding, no HTTPS quirks, and the Sidecar can be linked into the same address space as the agent for very tight latencies.

This is interesting when you're shipping a managed runtime (e.g. you control the agent SDK) and you want zero proxy footprint. It's not a starting mode — use HTTP proxy first, move to gRPC if and when proxy semantics become limiting.

### Unix socket

Same protocol as the HTTP proxy mode, but the listener is on a filesystem socket instead of a TCP port. Configured as:

```toml
[interceptor]
mode               = "unix_socket"
listen_addr        = "/run/firma-sidecar.sock"
drain_timeout_secs = 5
```

This is useful in three situations: (1) containerized environments where binding ports is constrained, (2) hosts with multiple tenants where port collisions are likely, and (3) any deployment where you want the Sidecar to be reachable only by processes that can also reach the filesystem path.

`firma run` uses Unix sockets internally to bridge sandboxed agents to the host-side Sidecar — see [The sandbox boundary](../sandbox/) for that path.

## HTTPS: CONNECT vs MITM

Modern agents talk HTTPS to nearly everything. An HTTP proxy can handle HTTPS in two fundamentally different ways, and the choice is consequential for what the policy can see.

### CONNECT relay

The agent sends `CONNECT api.example.com:443 HTTP/1.1`. The Sidecar opens a TCP connection to that host:port, replies `200 Connection Established`, and from then on **just relays bytes** between agent and origin. The TLS handshake happens between the agent and the origin; the Sidecar sees only encrypted traffic.

What you can enforce in CONNECT-only mode:

- Method: only `CONNECT` is observable.
- Host and port: from the CONNECT line.
- Nothing else: no path, no method (the inner one), no headers, no body.

That's enough for **destination-level policy**: "this agent may not contact `paste.rs`", "this agent may only contact `api.openai.com`". It's *not* enough for L7 policy: "no GET to `/admin/*`", or "no POST with body containing this key".

CONNECT-only is the right choice for hosts where you don't want to break end-to-end TLS — third-party SaaS where the operator hasn't authorized you to inspect, or services with certificate pinning that would reject MITM.

### TLS MITM

The Sidecar accepts the CONNECT, then **terminates TLS** with a certificate it generates on-the-fly using its own CA. The agent's TLS client sees a certificate signed by the Sidecar's CA (which the agent has been configured to trust). Inside that TLS session, the Sidecar decrypts the request, runs the full pipeline, then re-encrypts and forwards to the origin under a fresh outbound TLS connection.

What you can enforce in MITM mode:

- Everything from CONNECT mode, plus
- HTTP method, path, headers, body
- Full L7 action-class mapping (`POST /v1/payment_intents` → `payment.transfer`)
- Cedar context built from the actual request body via `intent.params`

MITM is the right choice for hosts you control or whose terms permit inspection — your own SaaS APIs, OpenAI / Anthropic / Stripe under explicit organizational policy, or your own internal services. It's also the only way to enforce mission-grade rules like "no Stripe transfer over $1000".

### Configuring per-host

`sidecar.toml` controls MITM scope with three lists:

```toml
[interceptor.https_mitm]
enabled         = true
intercept_hosts = ["api.openai.com", "api.anthropic.com", "api.stripe.com"]
bypass_hosts    = ["self-signed.internal"]
strict_hosts    = ["api.stripe.com"]
```

- **`intercept_hosts`** — explicit allowlist for MITM. Hosts in this list get TLS-terminated. Wildcards allowed (`*.anthropic.com`).
- **`bypass_hosts`** — explicit list to fall back to CONNECT-only. Use for hosts where MITM would break (cert pinning, mTLS) but you still want destination-level policy.
- **`strict_hosts`** — if MITM fails for any reason on these hosts (cert mismatch, handshake failure, internal error), **deny the connection** instead of falling back to CONNECT. Use for hosts where you'd rather break the call than enforce a weaker policy on it.

Hosts not in any list use the configured default (typically CONNECT-only).

For the operator-side workflow — generating the CA, trusting it on the agent host, choosing what to MITM — see [Enable HTTPS MITM](../../guides/https-mitm/).

## The CA: the most security-sensitive piece

When you enable MITM, the Sidecar mints a CA on first run (under `[ca].dir`). That CA's private key is the most sensitive secret in your OpenFirma deployment: anyone who possesses it can sign certificates that the agent host will trust. Two operational rules:

1. **Never regenerate the CA.** Once the agent host trusts it, you have to keep using it. Regenerating means you have to re-trust the new CA on every host. Treat the CA directory as immutable infrastructure.
2. **Restrict trust to the agent's host.** The CA should be installed in the trust store of *the agent's process*, not the operating system's global trust store. Tools like `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, or per-language equivalents let you scope trust narrowly. The bundled demo uses `SSL_CERT_FILE` for exactly this reason.

If the CA private key is ever exposed, the only correct response is to stop using MITM until you've issued a new CA, re-trusted it everywhere, and rotated anything the old CA might have signed for.

## Comparison and recommendation

| Need                                                | Recommended mode                       |
| --------------------------------------------------- | -------------------------------------- |
| Try OpenFirma against an existing agent             | HTTP proxy + CONNECT-only              |
| Local coding agent on your dev machine              | HTTP proxy + MITM for known hosts      |
| Containerized agent in a multi-tenant host          | Unix socket + MITM                     |
| Production web app calling LLM APIs                 | HTTP proxy + MITM, `strict_hosts` set  |
| Custom SDK with no proxy support                    | gRPC interceptor                       |
| Third-party agent talking to a host you don't own   | CONNECT-only via `bypass_hosts`        |

Start in CONNECT-only mode. Add MITM hosts as you decide which ones you want L7 policy on. Use `strict_hosts` for the small set of hosts you *cannot* afford to talk to under weaker rules.

## Where to go next

- [Connectors](../connectors/) — what happens to a request *after* the Sidecar allows it.
- [The sandbox boundary](../sandbox/) — how `firma run` forces traffic through the Sidecar even for agents that ignore env vars.
- [Enable HTTPS MITM](../../guides/https-mitm/) — operator-side walkthrough.
