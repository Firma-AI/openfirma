---
title: Capabilities
description: PASETO v4 tokens that prove an agent was authorized to attempt a class of action.
---

A **capability** is a short-lived, signed token that an agent presents to the Sidecar to prove "an Authority decided I'm allowed to attempt this kind of action". It is not a session token, not an API key, and not a bearer credential for the upstream service. It's a proof of authorization that lives entirely between the agent's runtime and the local enforcement plane.

Capabilities are the input to [Stage 1 of the pipeline](../pipeline/). Without one, no agent traffic reaches Stage 2 — and without an Authority that issued one, the agent runs with no privileges at all. This page explains what's inside a capability, how it gets validated, and why the design looks the way it does.

## What's inside

A capability is a [PASETO v4](https://paseto.io) public token. PASETO is a JWT-shaped format that fixes a long list of JWT footguns: there is exactly one signing algorithm (Ed25519 for `v4.public`), no `alg` field to confuse, and no symmetric variants that can be downgraded. The token is signed by the Authority and verified by the Sidecar using the Authority's public key.

The token's payload is a `CapabilityClaims` struct, defined in `firma-core`:

```json
{
  "token_id":     "79dd9ffb-ebc8-4883-8f1e-72eb74a26e33",
  "agent_id":     "demo-agent",
  "session_id":   "demo-session",
  "action_set":   ["communication.external.send"],
  "resource_scope": "wttr.in*",
  "issued_at":    "2026-05-04T20:34:08.760795+00:00",
  "expiry":       "2026-05-04T21:34:08.760795+00:00",
  "context_hash": "bb10f57aba7b2160477ac1dda07c197ba8d3540a54ed25cf81e36b650dce0fe2"
}
```

Every field has a job:

| Field            | Purpose                                                                                                 |
| ---------------- | ------------------------------------------------------------------------------------------------------- |
| `token_id`       | UUID v4 used as the revocation key. Lets you kill a single token without re-issuing every other one.    |
| `agent_id`       | The principal in Cedar policies (`Firma::Agent::"<agent_id>"`).                                         |
| `session_id`     | A logical session within an agent's lifetime. Lets the same agent run multiple isolated sessions.       |
| `action_set`     | The action classes this token authorizes. The Sidecar denies any class outside the set.                 |
| `resource_scope` | A glob over `host+path` that the resource must match. `*` means "any resource".                         |
| `issued_at`      | When the Authority signed it. Used to compute `session_duration_s` for policy context.                  |
| `expiry`         | Hard upper bound on validity. Stage 1 denies any token past expiry, with a small skew tolerance.        |
| `context_hash`   | SHA-256 of the Cedar context that was true at issuance time. Future use: bind tokens to a policy state. |

There is intentionally **no transport-specific field** — no URL, no method, no header value. Capabilities are a layer above HTTP. The same token authorizes an action class regardless of how the agent eventually delivers the call.

## How a capability is born

The Authority owns issuance. An agent (or an operator on behalf of an agent) sends an `IssuanceRequest`:

```text
agent_id:           "demo-agent"
session_id:         "demo-session"
requested_actions:  ["communication.external.send"]
resource_scope:     "wttr.in*"
requested_ttl:      3600
```

The Authority does three things in order:

1. **Issuance policy evaluation.** The Authority runs the request through a separate Cedar **issuance policy bundle**. This is where decisions like "this agent is not allowed to ever request `payment.transfer`" live. See [Policies](../policies/) for the issuance vs runtime split.
2. **TTL clamping.** The requested TTL is clamped to the Authority's `max_ttl_seconds` config (default 3600 in the demo). You cannot mint long-lived tokens by asking for them.
3. **Signing.** If issuance is allowed, the Authority assembles a `CapabilityClaims`, signs it with its Ed25519 key, and returns the PASETO token + the parsed claims.

In OpenFirma's reference Authority, you can do this from the CLI for development:

```bash
firma authority issue \
  --agent-id demo-agent \
  --session-id demo-session \
  --action communication.external.send \
  --resource-scope 'wttr.in*' \
  --ttl-seconds 3600 \
  --output capability-demo-agent.toml
```

The output is a TOML file with both the raw PASETO and the parsed claims, ready to be loaded into a Sidecar via `[capability_seed]` or used by `firma run --capability-file`. See [Issue capability tokens](../../guides/issue-capability-tokens/) for the full operator workflow.

## How a capability is validated

When the agent makes an outbound call, Stage 1 of the pipeline runs the validation flow:

1. **Selection.** The Sidecar's `CapabilityMap` is keyed by `(session_id, action_class, resource)`. It picks the capability that matches the normalized envelope. If none does, the result is `CapabilityNotFound` (a DENY).
2. **Signature verification.** The PASETO library verifies the Ed25519 signature against the Authority's public key, which the Sidecar holds in memory and never re-fetches on the hot path.
3. **Expiry check.** `now()` is compared against `expiry` with a configurable `clock_skew_tolerance_seconds` (default 5). Past expiry → `CapabilityExpired`.
4. **Revocation check.** `token_id` is looked up in the local revocation store — a bloom filter front, LRU cache for false positives. A hit → `CapabilityRevoked`.
5. **Scope match.** The request's normalized action class must be in `action_set`, and the resource must match `resource_scope`. A miss → `CapabilityScopeMismatch`.

If all five pass, Stage 1 emits a `ValidatedCapability` containing the raw token and parsed claims. The pipeline carries it forward into Stage 2 so policies can read `claims.agent_id`, `claims.session_id`, etc. Crucially, **policies do not have to verify the token themselves** — by the time Stage 2 sees the claims, they are already authoritative.

The whole stage is local. There is no network call, no Authority round-trip, no key fetch. This is what lets it stay under 1 ms p95.

## Revocation

A capability lives until its `expiry`. If you need to kill one earlier — say, an agent was compromised and you want to cut it off immediately — you publish a **revocation** for its `token_id`.

In the reference Authority, this is:

```bash
firma authority revocations add <token_id>
```

The Authority appends `token_id` to its revocation file and broadcasts a `RevocationEvent` over its `WatchRevocations` gRPC stream. Every connected Sidecar updates its local store as the event arrives. Propagation is sub-second in normal conditions.

The local store has two layers:

- A **bloom filter** sized for the expected number of active revocations (configurable via `[revocation].capacity` and `.fpr`). Lookups are constant-time and lock-free.
- An **LRU cache** that absorbs false-positive hits from the bloom and confirms whether a `token_id` is *actually* revoked (configurable via `[revocation].lru_capacity`).

This split is why revocation lookups stay under microseconds and why memory cost is bounded even with millions of historical revocations.

## Why capabilities and policies, not just policies

You might ask: if Stage 2 has the full power of Cedar, why bother with capabilities at all? Couldn't a single, expressive policy decide everything?

In principle, yes. In practice, the two-layer design buys three things:

1. **Pre-flight authorization.** Issuance is the right place for expensive checks: provenance, agent identity, multi-factor approval, human-in-the-loop. The Sidecar's hot path stays cheap because that work is already done by the time a token exists. A revoked capability turns into a fast bloom-filter miss.
2. **Cryptographic provability.** A signed token is non-repudiable evidence that *this Authority decided this agent was OK*. You can replay an audit log months later and verify, from cold, that the chain of authorizations actually existed.
3. **Operational decoupling.** Policy bundles get edited often (you tighten a rule, you push). Capabilities get issued at session start and stay stable. If the policy bundle is briefly missing or stale, capability validation continues working — and Stage 2 fails closed on stale bundles, so an old capability cannot bypass a tightening.

The two together form a textbook capability-based security model: the capability says "you have permission to attempt this", the policy says "given current conditions, this attempt is OK". Either alone is weaker.

## Where to go next

- [Policies](../policies/) — the Cedar bundles that Stage 2 evaluates against.
- [Issue capability tokens](../../guides/issue-capability-tokens/) — how an operator issues, distributes, and revokes.
- [The enforcement pipeline](../pipeline/) — see how validated claims flow into Stage 2.
