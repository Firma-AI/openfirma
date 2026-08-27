---
title: Capabilities
description: PASETO v4 tokens that prove an agent was authorized to attempt a class of action.
---

Capabilities are the input to [Stage 1 of the pipeline](../pipeline/). Without one, no agent traffic reaches Stage 2 — and without an Authority that issued one, the agent runs with no privileges at all. This page explains what's inside a capability, how it gets validated, and why the design looks the way it does.

## What's inside

A capability is a [PASETO v4](https://paseto.io) public token. PASETO is a JWT-shaped format that fixes a long list of JWT footguns: there is exactly one signing algorithm (Ed25519 for `v4.public`), no `alg` field to confuse, and no symmetric variants that can be downgraded. The token is signed by the Authority and verified by the Sidecar using the Authority's public key.

The token's payload is a `CapabilityClaims` struct, defined in `firma-core`:

```json
{
  "token_id":     "ctok_01j0000000e008000000000001",
  "agent_id":     "agt_01j0000000e008000000000001",
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
| `token_id`       | `ctok` TypeID backed by an RFC UUID v7. Used as the revocation key for one capability token.            |
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

1. **Issuance policy evaluation and narrowing.** The Authority treats requested action classes as a mathematical set, evaluates each unique class in canonical order against a separate Cedar **issuance policy bundle**, and **grants the authorized subset** — the intersection of what was requested and what the policy permits. Unauthorized classes are dropped, not fatal; the resulting `action_set` is sorted and duplicate-free. Only if *every* requested class is denied does issuance fail closed. This is where decisions like "this agent is not allowed to ever request `payment.transfer`" live. See [Policies](../policies/) for the issuance vs runtime split.
2. **TTL clamping.** The requested TTL is clamped to the Authority's `max_ttl` config (default `"1h"` in the demo). You cannot mint long-lived tokens by asking for them.
3. **Signing.** If at least one class is authorized, the Authority assembles a `CapabilityClaims` over the granted subset, signs it with its Ed25519 key, and returns the PASETO token + the parsed claims.

Because the Authority narrows, the caller can safely over-request. `firma run` does exactly that: by default it requests **all** action classes and lets the issuance policy decide the grant, so a session is never denied merely because its config omitted a class the mapping rules later emit. The policy — not the request — is the source of truth. Setting `[run.profiles.<name>.capability] requested_actions` in `firma.toml` narrows the request further, an opt-in knob for running with *fewer* permissions than the policy would allow.

In the normal `firma run` flow, this entire sequence happens automatically:
`firma run` calls the Authority's `IssueCapability` gRPC endpoint, receives the
signed token, writes it to
`$XDG_RUNTIME_DIR/firma/capabilities/<sandbox_id>.toml`, and the autostarted
sidecar loads it — no operator action required.

## Verify FirmaTeam capabilities

When `firma run` obtains capabilities from FirmaTeam, configure the workspace
public key on the run profile:

```toml
[run.profiles.codex.capability]
public_key_path = "/path/to/authority.pub"
refresh_ratio = 0.60
grace = "30s"
```

Export that key from FirmaTeam:

```bash
firma-authority export-workspace-public-key \
  --workspace-id <workspace> \
  --out /path/to/authority.pub
```

The file must contain exactly the 32 raw bytes of an Ed25519 public key. PEM,
OpenSSH, DER, hex, base64, and TOML encodings are not accepted. A relative
`public_key_path` is resolved from the `firma run` working directory.

`firma run` reads and validates the key before calling `IssueCapability`, then
uses it to verify the returned PASETO token. The same effective key is written
to the autostarted Sidecar's `[sidecar.authority].public_key_path`, so the
Sidecar verifies the generated capability seed against the same trust root.
The capability-specific path takes precedence over
`[sidecar.authority].public_key_path`; omitting it keeps the existing Sidecar
Authority key behavior.

Key read failures, files that are not exactly 32 bytes, malformed or expired
tokens, and signature mismatches fail closed with an error. The existing
`--capability-file` option and capability-seed TOML format are unchanged.

## Staying alive: automatic refresh

Capabilities are deliberately short-lived (the `firma run` default TTL is 15
minutes) so a leaked seed file is worthless within minutes. On its own, that
would stall a long agent session: once the token expires, Stage 1 denies every
protected call and the agent grinds to a halt.

`firma run` closes that gap with a background refresher. It re-calls the
Authority's `IssueCapability` RPC before the token expires — reusing the same
session identity and credentials it was launched with, so **no interactive
re-login ever happens** — and atomically rewrites the seed file with the fresh
token. Renewal fires partway through the token's life (by default at 60% of the
remaining lifetime, and always at least a grace window before expiry), never at
the moment of expiry.

The sidecar, in turn, **watches the seed file** and hot-swaps its in-memory
`CapabilityMap` the instant a new token lands — no restart, no dropped requests.
Reads on the hot path stay lock-free.

The whole loop is **fail-closed**. If the Authority is unreachable, the
refresher retries with backoff but never serves a stale token; the old one
simply expires and the sidecar denies until a refresh succeeds. If a rewritten
seed fails verification, the sidecar keeps the previous valid map rather than
installing an unverified one. And because every refresh is a fresh
`IssueCapability` call, the Authority's issuance policy (and any revocation) is
re-evaluated each cycle — a session that should lose access does, on the next
renewal.

Tuning knobs:

| Setting                                               | Where               | Default | Effect                                               |
| ----------------------------------------------------- | ------------------- | ------- | ---------------------------------------------------- |
| `run.profiles.<id>.capability.refresh_ratio`          | `firma run` profile | `0.60`  | Fraction of remaining lifetime before renewing.      |
| `run.profiles.<id>.capability.grace`                  | `firma run` profile | `"30s"` | Renew no later than this duration before expiry.     |
| `sidecar.capability_seed.hot_reload`                  | sidecar config      | `true`  | Watch the seed file and hot-swap the map on change.  |

There is intentionally no hard session-lifetime cap: the Authority's issuance
policy is the authority on whether a session may continue, and it is re-checked
on every refresh. If you need a fixed ceiling, enforce it there.

For the legacy operator path (pre-provisioning a fixed, long-lived session
without `firma run`), the CLI subcommand is available:

```bash
firma authority issue \
  --agent-id agt_01j0000000e008000000000001 \
  --session-id demo-session \
  --action communication.external.send \
  --resource-scope 'wttr.in*' \
  --ttl-seconds 3600 \
  --output capability-demo-agent.toml
```

The output is a TOML file with both the raw PASETO and the parsed claims. It can
be loaded into a Sidecar via `[sidecar.capability_seed]` (deprecated) or used by
`firma run --capability-file`. See [Issue capability tokens](../../guides/issue-capability-tokens/)
for that legacy workflow.

The `raw_token` is the source of truth. The other TOML fields are a parsed mirror for selection, diagnostics, and operator readability. At Sidecar startup, every seed is verified with the configured Authority public key, and the mirrored TOML claims must exactly match the claims inside the signed token. If someone edits `action_set`, `resource_scope`, `session_id`, or any other claim in the TOML without re-issuing and re-signing the token, the Sidecar refuses to start.

## How a capability is validated

When the agent makes an outbound call, Stage 1 of the pipeline runs the validation flow:

1. **Selection.** The Sidecar's `CapabilityMap` is keyed by `(session_id, action_class, resource)`. It picks the capability that matches the normalized envelope. If none does, the result is `CapabilityNotFound` (a DENY).
2. **Signature verification.** The PASETO library verifies the Ed25519 signature against the Authority's public key, which the Sidecar holds in memory and never re-fetches on the hot path.
3. **Expiry check.** `now()` is compared against `expiry` with a configurable `clock_skew_tolerance` (default `"5s"`). Past expiry → `CapabilityExpired`.
4. **Revocation check.** `token_id` is looked up in the local revocation store — a bloom filter front, LRU cache for false positives. A hit → `CapabilityRevoked`.
5. **Scope match.** The request's normalized action class must be in `action_set`, and the resource must match `resource_scope`. A miss → `CapabilityScopeMismatch`.

If all five pass, Stage 1 emits a `ValidatedCapability` containing the raw token and parsed claims. The pipeline carries it forward into Stage 2 so policies can read `claims.agent_id`, `claims.session_id`, etc. Crucially, **policies do not have to verify the token themselves** — by the time Stage 2 sees the claims, they are already authoritative.

The whole stage is local. There is no network call, no Authority round-trip, no key fetch. This is what lets it stay under 1 ms p95.

Capabilities written under `$XDG_RUNTIME_DIR/firma/capabilities/` by `firma run`
are loaded by the sidecar at startup using the same verification path. Operator-
configured `[sidecar.capability_seed]` paths are also loaded (deprecated; see
[Issue capability tokens](../../guides/issue-capability-tokens/)), but emit a
deprecation warning. In both cases the sidecar verifies each seed's `raw_token`
and rejects the seed if the signed claims differ from the TOML mirror. This moves
tamper detection to boot time instead of waiting for the first matching request.

## Revocation

A capability lives until its `expiry`. If you need to kill one earlier — say, an agent was compromised and you want to cut it off immediately — you publish a **revocation** for its `token_id`.

Capability token IDs use the canonical form `ctok_<26-character TypeID suffix>`.
Raw UUIDs and TypeIDs with another prefix or UUID version are rejected by token,
seed, and revocation ingestion.

In the reference Authority, this is:

```bash
firma authority revocations add <token_id>
```

The Authority appends `token_id` to its revocation file and broadcasts a `RevocationEvent` over its `WatchRevocations` gRPC stream. Every connected Sidecar updates its local store as the event arrives. Propagation is sub-second in normal conditions.

The local store has two layers:

- A **bloom filter** sized for the expected number of active revocations (configurable via `sidecar.revocation.capacity` and `sidecar.revocation.fpr`). Lookups are constant-time and lock-free.
- An **LRU cache** that absorbs false-positive hits from the bloom and confirms whether a `token_id` is _actually_ revoked (configurable via `sidecar.revocation.lru_capacity`).

This split is why revocation lookups stay under microseconds and why memory cost is bounded even with millions of historical revocations.

## Why capabilities and policies, not just policies

You might ask: if Stage 2 has the full power of Cedar, why bother with capabilities at all? Couldn't a single, expressive policy decide everything?

In principle, yes. In practice, the two-layer design buys three things:

1. **Low latency.** Issuance is the right place for expensive checks: provenance, agent identity, multi-factor approval, human-in-the-loop. The Sidecar's hot path stays cheap because that work is already done by the time a token exists. A revoked capability turns into a fast bloom-filter miss.
2. **Auditability.** A signed token is non-repudiable evidence that _this Authority decided this agent was OK_. You can replay an audit log months later and verify, from cold, that the chain of authorizations actually existed.
3. **Operational safety.** Policy bundles get edited often (you tighten a rule, you push). Capabilities get issued at session start and stay stable. If the policy bundle is briefly missing or stale, capability validation continues working — and Stage 2 fails closed on stale bundles, so an old capability cannot bypass a tightening.

The two together form a textbook capability-based security model: the capability says "you have permission to attempt this", the policy says "given current conditions, this attempt is OK". Either alone is weaker.

## Where to go next

- [Policies](../policies/) — the Cedar bundles that Stage 2 evaluates against.
- [Issue capability tokens](../../guides/issue-capability-tokens/) — how an operator issues, distributes, and revokes.
- [The enforcement pipeline](../pipeline/) — see how validated claims flow into Stage 2.
