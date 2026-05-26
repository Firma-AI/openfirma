---
title: Policies
description: How Cedar policies decide ALLOW or DENY at issuance time and at request time.
---

Policies are Cedar rules that turn a normalized OpenFirma action into an `ALLOW` or `DENY` decision, first when the Authority issues a capability and again when the Sidecar evaluates each request. At this point we assume you've read [Capabilities](../capabilities/) and [Action classes](../action-classes/). It covers the two policy surfaces, the entity model, what's in the runtime context, and the basic pattern language.

## Two policy surfaces

OpenFirma has two distinct sets of Cedar policies:

| Surface          | Run by    | When                                 | Decides                                                         |
| ---------------- | --------- | ------------------------------------ | --------------------------------------------------------------- |
| **Issuance**     | Authority | Pre-flight, when minting a token     | "Should this agent ever be allowed to attempt this class?"      |
| **Runtime**      | Sidecar   | On every outbound call, in Stage 2   | "Given current conditions, is this specific call OK right now?" |

The split matters because the two surfaces answer fundamentally different questions:

- **Issuance** policies are about *agent identity and mission*. "This agent is supposed to do `model.inference.chat` and nothing else" is an issuance policy. It is evaluated rarely (once per session), so it can afford expensive checks.
- **Runtime** policies are about *the current world*. "Don't allow `payment.transfer` over $1,000 today" is a runtime policy. It runs on every request, so it must be cheap and deterministic.

A capability that an issuance policy approved is still subject to runtime policy. The two layers compose.

## The entity model

Every Cedar policy in OpenFirma speaks the same three-entity language:

```text
principal: Firma::Agent::"<agent_id>"
action:    Firma::Action::"<action_class>"
resource:  Firma::Resource::"<host><path>"
```

A simple permit looks like:

```cedar
permit (
    principal == Firma::Agent::"example-agent",
    action == Firma::Action::"communication.internal.send",
    resource
);
```

Cedar's default is **deny** — if no policy explicitly permits an action, it's denied. And a `forbid` rule **overrides** any matching `permit`. This is "default deny, forbid wins", and it's exactly what you want at a security boundary: removing a permit narrows what's allowed; adding a forbid narrows further; nothing about adding a rule can accidentally grant new permissions.

The schema is shared between Authority and Sidecar — `examples/demo/policies/schema.cedarschema` is the source of truth. The 15 base FEP action classes plus extensions are declared there. If you reference a class that isn't in the schema, Cedar refuses to compile the policy at all — a malformed bundle never reaches the hot path.

## The runtime context

When Stage 2 evaluates a runtime policy, it builds a Cedar context with exactly these fields (see `crates/firma-sidecar/src/enforcement/constraint_enforcement.rs` and `schema.cedarschema`):

| Field                | Type   | Meaning                                                |
| -------------------- | ------ | ------------------------------------------------------ |
| `session_id`         | String | Session this call belongs to                           |
| `timestamp_ms`       | Long   | Wall clock at evaluation, Unix epoch milliseconds      |
| `params`             | String | JSON-serialized `intent.params` (the request body)     |
| `risk_score`         | Long   | Static or pre-computed; V1 always emits `0`            |
| `budget_remaining`   | Long   | Remaining budget from the capability ceiling           |
| `session_duration_s` | Long   | Seconds since `claims.issued_at`                       |
| `action_count`       | Long   | Monotonic per-session counter, 1-based                 |
| `raw_transport`      | String | `"http"` or `"https"`                                  |

These are the only signals available to a runtime policy. There is intentionally no live agent telemetry, no upstream response data, no LLM signal. That keeps Stage 2 deterministic and under its 200 µs budget.

A policy that uses context looks like:

```cedar
forbid (
    principal,
    action == Firma::Action::"communication.external.send",
    resource
) when {
    context.risk_score >= 80
};
```

## Basic patterns

A few rules cover most of what you'll write.

### Permit a specific class for a specific agent

```cedar
permit (
    principal == Firma::Agent::"example-agent",
    action == Firma::Action::"model.inference.chat",
    resource
);
```

This is the building block for least-privilege agents. Bind `principal` to the exact agent id and only enumerate the classes that agent's mission requires.

### Forbid a destination for everyone

```cedar
forbid (
    principal,
    action == Firma::Action::"communication.external.send",
    resource == Firma::Resource::"paste.rs/"
);
```

`forbid` rules without a specific `principal` apply to all agents. This is the right shape for "we never want anything to talk to this host", regardless of which agent is misbehaving today. Note the `paste.rs/` form — the resource UID is the host plus the normalized path, and an empty path is `/`.

### Match on parameters

The full request body is available to Cedar as `context.params` (a JSON string). Useful for limits like:

```cedar
forbid (
    principal,
    action == Firma::Action::"payment.transfer",
    resource
) when {
    context.params has "amount" &&
    context.params.amount > 100000
};
```

This pattern is what `examples/policies/payment.cedar` builds on for the payment-splitting example, where cumulative counters are pre-computed off the hot path and exposed as additional context fields.

### Action sets

Multiple classes can be matched in one rule:

```cedar
forbid (
    principal,
    action in [
        Firma::Action::"credential.read",
        Firma::Action::"credential.write"
    ],
    resource
) when {
    context.risk_score >= 60
};
```

Use this for category-wide forbids — the rule is shorter and harder to drift.

## Bundle freshness

The Sidecar holds the policy bundle in memory and reloads it from the Authority's `WatchPolicyBundle` gRPC stream. Two configuration knobs in `firma.toml` govern freshness:

```toml
[sidecar.constraint_enforcement]
bundle_ttl_seconds     = 60   # bundles older than this are considered stale
enforcement_timeout_ms = 50   # max time Stage 2 will spend evaluating
```

If the bundle hasn't been refreshed within `bundle_ttl_seconds`, Stage 2 returns `PolicyBundleStale` — every request denies. This is fail-closed by design: stale policy is *not* better than no policy, because the world might have changed in ways the stale policy doesn't reflect.

When the Authority comes back, the next bundle update atomically swaps the evaluator. There's no flush-and-reload window.

## Where to go next

- [Write your first Cedar policy](../../guides/write-a-cedar-policy/) — hands-on, with hot-reload through the Authority.
- [Capabilities](../capabilities/) — how a capability gets minted under issuance policy.
- [Action classes](../action-classes/) — the vocabulary the policies reference.
