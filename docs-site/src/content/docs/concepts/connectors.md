---
title: Connectors
description: How an allowed request actually reaches the upstream service — the egress half of the Sidecar.
---

[Interception](../interception/) is how a request enters the Sidecar. **Connectors** are how it leaves. Once both stages of the [pipeline](../pipeline/) have allowed a call, the connector is responsible for actually dispatching it to the upstream system, handling failures, applying per-host limits, and (where configured) injecting credentials.

This page explains what connectors do, why they sit *outside* the enforcement boundary, and how to configure them for real workloads.

## What the connector does

A connector is the egress component of the Sidecar. Concretely, it:

1. Takes the original `RawRequest` plus the `Decision::Allow` from the pipeline.
2. Optionally **injects credentials** (e.g. an `Authorization` header pulled from a secret store).
3. Applies **per-host rate limits** (requests per second, burst, timeout).
4. Forwards the request to the upstream over plain TCP (HTTP) or a fresh outbound TLS connection (HTTPS, when MITM is in use).
5. Streams the response back to the agent.
6. Translates upstream errors into a typed `ConnectorError` so the audit log records the outcome.

The Sidecar ships with a single connector implementation today: a generic HTTP/HTTPS connector that handles every upstream the mapping table can route to. It is configured per-host, not per-class — the same connector handles `api.stripe.com` and `wttr.in`, but with different limits for each.

## Why the connector is outside the enforcement boundary

This is a design choice worth understanding. The connector is downstream of the Stage 1 / Stage 2 chain, which means:

- A `DENY` from either stage **short-circuits before the connector ever sees the request**. There is no code path in which a denied request can leak through a connector misconfiguration.
- The connector cannot see, modify, or override decisions. It just dispatches what was allowed.
- Adding new connectors (in the future, for non-HTTP transports) does not enlarge the enforcement surface. Whatever a new connector does to a request, it does to a request the policy already approved.

Conversely, an `ALLOW` means the request is forwarded **as the agent submitted it**, modulo credential injection. The Sidecar does not rewrite payloads, does not synthesize fields, does not "fix up" what the agent sent. If you want behavior to change, the place to express it is policy — not the connector.

## Configuring per-host limits

Default timeout and per-host overrides live under `[connector]` in `sidecar.toml`. The demo's config is a useful template:

```toml
[connector]
default_timeout_ms = 30000

[[connector.hosts]]
host       = "wttr.in"
rps        = 60
burst      = 10
timeout_ms = 30000

[[connector.hosts]]
host       = "paste.rs"
rps        = 60
burst      = 10
timeout_ms = 30000

[[connector.hosts]]
host       = "127.0.0.1:9100"
rps        = 200
burst      = 50
timeout_ms = 30000
```

| Field        | Meaning                                                                                          |
| ------------ | ------------------------------------------------------------------------------------------------ |
| `host`       | The upstream the limits apply to. Exact match — wildcards aren't supported here.                 |
| `rps`        | Steady-state allowed requests per second.                                                        |
| `burst`      | Token-bucket burst size; absorbs short spikes above `rps`.                                       |
| `timeout_ms` | Per-request timeout. Beyond this, the connector returns `ConnectorError::Timeout` and denies.    |

Hosts not listed use `default_timeout_ms` and no rate limit. Set sensible defaults for any host that's part of your normal agent workload — both to protect the upstream and to bound the blast radius of a runaway agent loop.

## Credential injection

The connector is also where credentials for upstream services are attached. This is a deliberate choice: the agent never holds the secret, the policy decides whether the call is OK, and only then does the connector add the credential.

The `[credentials.*]` blocks declare what to inject for which host:

```toml
[[credentials]]
host           = "api.openai.com"
mode           = "basic"
header         = "Authorization"
value_from_env = "OPENAI_API_KEY"
prefix         = "Bearer "
```

Two modes are supported today:

- **`basic`** — pulls the value from an environment variable on the Sidecar host and prepends an optional prefix.
- **`vault`** — pulls the value from a HashiCorp Vault path. Requires `[credentials].secret_path` and Vault auth configured.

The injection happens after `Decision::Allow` and before dispatch. If injection fails (env var missing, Vault unreachable), the connector returns a typed error, the call is denied, and the audit event records what happened.

For the operator workflow, see [Inject credentials](../../guides/inject-credentials/).

## Errors and the audit log

When the connector dispatches a call, four things can happen:

| Outcome         | What it means                                                  | Audit shape                            |
| --------------- | -------------------------------------------------------------- | -------------------------------------- |
| Success         | Upstream returned a response (any HTTP status).                | `Decision::Allow` + upstream status    |
| `Timeout`       | Upstream did not respond within `timeout_ms`.                  | `Decision::Allow` (policy-allowed) + connector error |
| `Network`       | Connection failed (DNS, TCP, TLS handshake).                   | `Decision::Allow` + connector error    |
| `InvalidRequest`| Upstream rejected the request shape (e.g. malformed body).     | `Decision::Allow` + connector error    |

Note the subtle but important point: a connector failure does **not** retroactively turn an `Allow` into a `Deny` in the audit log. The policy decision is recorded as it happened, *and* the connector failure is recorded separately. This preserves the determinism invariant: the same envelope plus the same bundle would have produced the same `Allow` regardless of whether the network later cooperated.

## Why a single connector implementation today

V1 ships a single generic HTTP connector and intentionally does not expose connector pluggability as an extension surface. There are good reasons for this:

- **Most upstreams agents talk to are HTTP-shaped.** OpenAI, Anthropic, Stripe, GitHub, Slack, internal SaaS — they're all HTTP/HTTPS over TLS. One connector handles them all.
- **The enforcement boundary stays small.** A pluggable connector surface would be a place for vendors to ship "smart" wrappers that re-litigate decisions or alter payloads. Keeping the surface frozen prevents that.
- **Per-host configuration is enough.** Most differentiation between upstreams is rate limits, timeouts, and credentials — all configurable today without code.

Future work may add connectors for non-HTTP transports (gRPC streaming to upstreams, message queues, etc.) where the request shape is fundamentally different. Until that's needed, the single-connector design keeps the system honest.

## What connectors are *not*

A few common misunderstandings:

- **Connectors are not policy.** They cannot deny a request on their own. If you want a request blocked, write a policy rule.
- **Connectors do not buffer.** A request is forwarded as it streams in; the connector is not a place to inspect bodies or apply transformations.
- **Connectors do not retry.** A failed dispatch is a single attempt. If you need retry semantics, that's the agent's job — and policies should consider that retries inflate `action_count`.
- **Connectors are not load balancers.** A request goes to the host it was addressed to. There is no ingress shape, no upstream selection, no traffic splitting.

## Where to go next

- [Inject credentials](../../guides/inject-credentials/) — operator workflow for `[credentials.*]`.
- [Read & verify the audit log](../../guides/audit-log/) — what connector outcomes look like in audit events.
- [The sandbox boundary](../sandbox/) — how mandatory routing pairs with connectors.
