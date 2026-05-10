---
title: Architecture & invariants
description: How the OpenFirma processes fit together, and the four invariants that shape every design choice.
---

OpenFirma is a *governed runtime* for AI agents. It sits between an agent and the outside world, decides whether each outbound call is allowed, and writes a signed record of what happened. This page introduces the moving parts and the four invariants that the rest of the documentation builds on.

## The processes

A working OpenFirma deployment runs three processes:

```text
┌──────────────────┐      outbound HTTP/HTTPS      ┌──────────────────┐
│      Agent       │  ───────────────────────────► │     Sidecar      │
│ (LLM, codegen,   │   HTTP_PROXY + trusted CA     │  (enforcement    │
│  webapp, …)      │                               │   point)         │
└──────────────────┘                               └────────┬─────────┘
                                                            │
        ┌───────────────────────────────────────────────────┘
        │ pre-flight (token issuance + policy stream)
        ▼
┌──────────────────┐
│    Authority     │
│  (signing,       │
│   policy bundle, │
│   revocations)   │
└──────────────────┘
```

- **Agent** — any process that makes outbound calls. OpenFirma does not care whether it is an LLM agent loop, a code generator, or a web service that occasionally calls a model.
- **Sidecar** — the enforcement point. It captures the agent's outbound traffic, decides whether to allow each call, and emits a signed audit event. It runs locally to the agent: no network hop on the decision path.
- **Authority** — the trust root. It mints short-lived **capability tokens** for an agent before a session starts, and streams **policy bundles** and **revocations** to the Sidecar in the background.

A fourth process is optional but common: **`firma run`**, a sandbox wrapper that launches an agent with the right environment variables and a sandbox identity so that all of its traffic is forced through the Sidecar. See [The sandbox boundary](../sandbox/) for when to use it.

## The request lifecycle

When the agent makes an outbound HTTP call, this is the path it takes:

1. The Sidecar **intercepts** the request (proxy, gRPC hook, or Unix socket — see [Interception](../interception/)).
2. The **normalizer** maps `(method, host, path)` to a canonical *action class* like `communication.external.send`. See [Action classes](../action-classes/).
3. **Stage 1 — Capability validation**: the Sidecar finds a [capability token](../capabilities/) for this `(session, action_class, resource)`, verifies its PASETO signature, checks expiry, checks revocation. Target: under 1 ms p95.
4. **Stage 2 — Constraint enforcement**: the Sidecar evaluates the action against the current [Cedar policy bundle](../policies/).
5. If both stages allow, the [connector](../connectors/) dispatches the call upstream and (optionally) injects credentials.
6. Either way — allow or deny — a signed audit event is emitted.

The full path is covered in [The enforcement pipeline](../pipeline/).

## The four invariants

Every design decision in the codebase is anchored to four invariants. If you ever wonder *why is it built this way*, the answer is almost always one of these.

### 1. Fail-closed

Every error becomes a `DENY` decision. There is no error path that silently allows a call. A malformed token, a missing policy bundle, a normalizer crash, an unreachable Authority — all of these block traffic instead of letting it through.

This is uncomfortable in development (you'll see denies you didn't expect), but it's the only honest posture for a security boundary. A system that *sometimes* enforces is not enforcing.

### 2. No network on the hot path

Stage 1 and Stage 2 are fully local: token validation uses an in-memory copy of the Authority's public key, policy evaluation uses an in-memory copy of the Cedar bundle, and revocation lookups go to an in-memory bloom filter + LRU cache.

The Authority is only contacted **before** a session starts (to issue tokens) and **in the background** (to stream policy and revocation updates). The decision path itself never blocks on a network call. This is what makes the performance budget achievable.

### 3. Determinism

Same input plus same policy bundle produces the same decision. There is no probabilistic classifier, no LLM, no model inference on the decision path. The mapping from `(method, host, path)` to action class is a deterministic table lookup. Cedar evaluation is by design total and deterministic.

If the Sidecar denies a call, you can reproduce that decision exactly given the same envelope and bundle. This matters for debugging, for incident response, and for compliance.

### 4. Envelope immutability

Once the Sidecar has built the `ExecutionEnvelope` for a request — the canonical representation of *what the agent is trying to do* — it is never mutated. Enrichment steps (like injecting credentials before dispatch) produce derived structures rather than editing the envelope in place.

This sounds pedantic but it pays off: the audit log records the exact envelope that the policy decided on, so you can replay decisions, you can sign the envelope as part of the audit event, and you can reason about state transitions without worrying about hidden side effects.

## What this enables

These four invariants together give you something that most "AI guardrail" products do not:

- A **policy-mediated** outbound boundary that holds even when the agent is compromised, mis-prompted, or bug-ridden.
- A **deterministic** record of every decision, not just a sample.
- **Microsecond-class** decisions, so the boundary is cheap enough to leave on in production.
- A **provable** scope: the agent cannot escape it without you noticing, because escape paths produce DENY events you can alert on.

The rest of the Concepts section unpacks how each piece works. The User Guides section shows how to put it together for real workloads.

## Where to go next

- [The enforcement pipeline](../pipeline/) — how the two stages chain together.
- [Action classes](../action-classes/) — the canonical vocabulary the policies speak.
- [Quickstart](../../quickstart/) — run the bundled demo end-to-end.
