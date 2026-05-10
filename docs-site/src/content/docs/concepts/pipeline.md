---
title: The enforcement pipeline
description: How the Sidecar turns a raw agent request into an ALLOW or DENY decision in microseconds.
---

The enforcement pipeline is the heart of OpenFirma. It runs inside the Sidecar and decides whether each outbound agent call is allowed. This page walks through the pipeline stage by stage so that, by the end, you can read an audit event and know *exactly* which check it passed or failed.

If you have not yet read [Architecture & invariants](../architecture/), start there: the four invariants (fail-closed, no network on hot path, determinism, envelope immutability) explain why the pipeline is shaped the way it is.

## The pipeline at a glance

```text
┌─────────────┐    ┌────────────┐    ┌──────────────────┐    ┌──────────────────┐    ┌────────────┐
│ Interceptor │ ─► │ Normalizer │ ─► │ Stage 1          │ ─► │ Stage 2          │ ─► │ Connector  │
│             │    │            │    │ Capability       │    │ Constraint       │    │            │
│             │    │            │    │ validation       │    │ enforcement      │    │            │
└─────────────┘    └────────────┘    └──────────────────┘    └──────────────────┘    └────────────┘
                                                  │                          │
                                                  └──────────┬───────────────┘
                                                             ▼
                                                      ┌────────────┐
                                                      │ Audit sink │
                                                      └────────────┘
```

The pipeline has a single entry point — `enforce()` in `firma_sidecar::pipeline`. Every interceptor (HTTP proxy, gRPC, Unix socket) feeds requests to the same entry point, and the rest of the pipeline does not care which interceptor produced the request.

A request that reaches the **Connector** has been allowed by both stages. A request that fails any stage **never** reaches the upstream system. Both outcomes produce an audit event.

## Stage 0: Interception and normalization

Before the two enforcement stages run, two preparation steps happen.

**Interception** captures the outbound call. There are three modes — see [Interception](../interception/) for the full picture. For the purposes of this page, assume the Sidecar has just received a `RawRequest` containing the method, host, path, headers, and (optionally) the body.

**Normalization** turns the raw request into the canonical envelope the rest of the pipeline operates on. Concretely it:

1. Looks up `(method, host, path)` in the mapping table and produces an `intent.action_class` (e.g. `communication.external.send`).
2. Extracts the `intent.resource` map with conventional keys `host`, `path`, and optionally `provider` (when the host matches a known allowlist like `api.github.com` → `provider="github"`).
3. Strips sensitive headers (cookies, authorization) so they don't end up in the audit log.
4. Builds the `ExecutionEnvelope` — an immutable record of *what the agent is trying to do*.

If the request is **unclassifiable** (no rule matches, and the mapping table is configured fail-closed), normalization itself produces a DENY. This is the first line of defense: an unmapped call is a call you have not thought about yet.

## Stage 1: Capability validation

Stage 1 answers a single question: **does the agent currently hold a valid capability for this action?**

A capability is a [PASETO v4 token](../capabilities/) that the Authority issued before the session started. It carries claims like:

```json
{
  "agent_id": "demo-agent",
  "session_id": "demo-session",
  "action_set": ["communication.external.send"],
  "resource_scope": "wttr.in*",
  "issued_at": "2026-05-04T20:34:08Z",
  "expiry":    "2026-05-04T21:34:08Z",
  "context_hash": "bb10f57aba…"
}
```

Stage 1 does five things, in order:

1. **Token selection** — looks up the capability in the in-memory `CapabilityMap` keyed by `(session_id, action_class, resource)`.
2. **Signature verification** — verifies the PASETO v4 signature using the Authority's public key (held in memory; never fetched on the hot path).
3. **Expiry check** — compares `expiry` against the wall clock, with a configurable `clock_skew_tolerance_seconds`.
4. **Revocation check** — looks up the `token_id` in the local revocation store (a bloom filter front, LRU cache for false positives).
5. **Scope match** — confirms the requested action and resource fall inside `action_set` and `resource_scope`.

If any of these fail, Stage 1 returns a typed `DenyReason` (e.g. `CapabilityExpired`, `CapabilityRevoked`, `CapabilityNotFound`) and the pipeline short-circuits — Stage 2 does not run.

The whole stage targets **under 1 ms p95** in production. There is no network call.

## Stage 2: Constraint enforcement

Stage 2 answers a different question: **is this action permitted by the current policy?**

A capability says *the agent is allowed to attempt this class of action*. A policy says *given the current context, is this specific call OK*. The split matters: a token outlives a single decision (typically an hour), but the policy bundle can be updated continuously, so you can tighten or relax rules without re-issuing tokens.

Stage 2:

1. **Bundle freshness** — checks that the in-memory Cedar policy bundle is younger than `bundle_ttl_seconds`. A stale bundle (Authority unreachable for too long) produces a `PolicyBundleStale` deny. This is what makes the system fail-closed when control-plane connectivity is lost.
2. **Cedar evaluation** — calls the Cedar evaluator with the principal (`Firma::Agent::"<agent_id>"`), action (`Firma::Action::"<action_class>"`), resource (`Firma::Resource::"<host+path>"`) and a context object (see below).
3. **Decision encoding** — turns Cedar's `Allow` / `Deny` result into the Sidecar's `Decision` type, attaching the matched policy IDs.

The Cedar context contains exactly the fields the schema in `examples/demo/policies/schema.cedarschema` declares:

| Field                | Type   | Source                                                  |
| -------------------- | ------ | ------------------------------------------------------- |
| `session_id`         | String | from the validated capability claims                    |
| `timestamp_ms`       | Long   | wall clock at evaluation time                           |
| `params`             | String | JSON-serialized `intent.params`                         |
| `risk_score`         | Long   | static or pre-computed (V1 = `0`)                       |
| `budget_remaining`   | Long   | `budget_ceiling` minus consumed; `i64::MAX` when unset  |
| `session_duration_s` | Long   | seconds since `claims.issued_at`                        |
| `action_count`       | Long   | monotonic per-session counter, 1-based                  |
| `raw_transport`      | String | `"http"` or `"https"`, set by the normalizer            |

These are the only signals a policy can look at. There is intentionally no live agent telemetry on the decision path — that would violate the no-network and determinism invariants.

Stage 2 targets **under 200 µs p95**. Cedar evaluation is by design total: the same bundle plus the same context produces the same decision every time.

## Audit emission

Both stages — and the connector dispatch — produce an `AuditPayload`. The payload includes:

- the canonical `ExecutionEnvelope` (the agent's intent),
- the `Decision` (allow / deny + reason + matched policy IDs),
- the validated `CapabilityClaims` (or the deny reason that prevented validation),
- timestamps and identifiers.

A separate worker signs the payload with an ECDSA P-256 key off the hot path and writes it to the configured sink (stdout, file, gRPC, or WAL). Signing **never blocks** the request — the Sidecar acknowledges the decision to the agent first, then the audit worker handles delivery.

For more on reading and verifying audit events, see [Read & verify the audit log](../../guides/audit-log/).

## Why the pipeline is shaped this way

A few specific design choices are worth calling out, because they are easy to miss:

- **The two stages are independent.** Stage 1 is about *who you are and what you proved at issuance time*. Stage 2 is about *what the world looks like right now*. Separating them lets the Authority do expensive work upfront (Cedar issuance evaluation, signing) and lets the Sidecar do cheap work on the hot path (signature verification, table lookup, Cedar runtime evaluation).

- **Both stages must pass.** A valid capability is not enough — the runtime policy gets the final word. A passing policy is not enough — the agent must hold a capability that proves it was authorized to attempt this. This is the principle of **least privilege at two timescales**: long-lived tokens scoped to the agent's mission, short-lived policy that can react to new threats.

- **Short-circuiting matters for the audit log.** If Stage 1 denies, Stage 2 does not run, and the audit event reflects that the deny was at the *capability* level — not at the *policy* level. When you read the log later, you can tell whether the agent had no business making the call, or whether the call was OK in principle but blocked by current policy.

- **The connector is outside the enforcement boundary.** A `DENY` short-circuits before the connector ever sees the request, so you cannot accidentally leak data by misconfiguring the connector. Conversely, an `ALLOW` means the request is forwarded *as the agent submitted it* (modulo credential injection) — the Sidecar does not rewrite payloads.

## Where to go next

- [Action classes](../action-classes/) — the vocabulary the normalizer produces and the policies speak.
- [Capabilities](../capabilities/) — what's inside a token and how it's validated.
- [Policies](../policies/) — how to write Cedar rules that decide ALLOW / DENY.
- [Read & verify the audit log](../../guides/audit-log/) — turn this conceptual flow into something you can grep.
