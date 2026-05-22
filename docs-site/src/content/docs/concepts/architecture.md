---
title: Architecture & invariants
description: How the OpenFirma processes fit together, and the four invariants that shape every design choice.
---

OpenFirma is a runtime boundary for AI agents. It does not judge the model's thoughts, prompts, or chain of reasoning. It controls the concrete thing an agent process eventually does: outbound traffic.

## Architecture

```mermaid
flowchart LR
    authority["Authority"]
    agent["Agent process"]
    sidecar["Sidecar"]
    upstream["External service"]
    audit["Signed audit log"]

<<<<<<< Updated upstream
    subgraph dataPath["Data path: every outbound request"]
        agent["Agent process"]
        sidecar["Sidecar"]
        upstream["External service"]
        audit["Signed audit log"]
        agent -->|"HTTP or HTTPS request"| sidecar
        sidecar -->|"ALLOW or PASSTHROUGH"| upstream
        sidecar -->|"DENY / ABORT"| agent
        sidecar -->|"Decision event"| audit
    end

    firmaRun["firma run"] -. "sandbox launcher (optional)" .-> agent
    sidecarState -. "Used locally by" .-> sidecar
=======
    agent -->|"Outbound calls"| sidecar
    sidecar -->|"ALLOW"| upstream
    sidecar -->|"DENY / ABORT"| agent
    sidecar --> audit
    authority -. "Capabilities, policies, revocations" .-> sidecar
>>>>>>> Stashed changes
```

> **Intercepted call types:** plain HTTP, HTTPS (tunnel or transparent MITM), gRPC, Unix domain socket, and local shell commands via `local_exec`.

The **Authority** is the trust root. It issues short-lived capability tokens and streams policy bundles and revocation updates to connected Sidecars. It is never on the enforcement hot path: every allow/deny decision is fully local.

The **Sidecar** is the local enforcement point. It intercepts every outbound call, classifies it into a canonical action class, validates the capability token, evaluates Cedar policy, and on ALLOW injects credentials and dispatches the call. Every outcome produces a signed audit event.

<<<<<<< Updated upstream
`firma run` is the optional launcher. It starts the agent inside a sandbox and routes network traffic toward the Sidecar. Without it, proxy environment variables can route cooperative agents. With it, bypassing the Sidecar is much harder. The sandbox backend is selected by platform: `bwrap` on Linux, `vz` (via `sandbox-exec`) on macOS, and `wsl2` on Windows.

Before any request is evaluated, the Sidecar checks that its local state is ready: both the policy bundle and the revocation cache must be hydrated. If either is missing or stale, the pipeline denies protected traffic immediately. This readiness check runs before normalization and before any enforcement stage.
=======
The **Audit emitter** writes a signed record for every enforcement decision. It runs as a background task inside the Sidecar, draining into a file, stdout, a remote service, or a local write-ahead log.
>>>>>>> Stashed changes

## The four invariants

These invariants explain behaviors you will encounter while working with OpenFirma.

### Fail closed

Uncertainty becomes DENY. Unknown mapping, missing capability, expired token, stale policy, unavailable policy evaluator, malformed request, failed credential fetch: all of these block the request.

In practice: if you add a new SaaS endpoint but forget to add a mapping rule, you will see a DENY with `UnclassifiedIntent` in the audit log, not a silent pass-through. Before any request is evaluated, the Sidecar also checks that its local state is ready: both the policy bundle and the revocation cache must be hydrated. If either is missing or stale, protected traffic is denied immediately.

### No network on the enforcement hot path

The Sidecar does not call the Authority to decide whether to allow or deny a request. Capability validation and Cedar policy evaluation run against local state only.

In practice: if the Authority goes down mid-session, the Sidecar keeps enforcing against its cached state. Once that state exceeds its freshness threshold, it denies. You will never get a silent pass-through because the control plane is unreachable.

### Determinism

The enforcement decision is deterministic for the same normalized request, local capability state, runtime signals, and policy bundle. There is no LLM or probabilistic classifier in the decision path.

In practice: if a request was denied because `action_count` exceeded a threshold, you can inspect the audit event and the Cedar bundle and reproduce the exact decision. You are not debugging a model judgment.

### Envelope immutability

The Sidecar builds a canonical `ExecutionEnvelope` once, before enforcement. Policy evaluates that envelope. Audit records that envelope. Credential injection and connector dispatch happen after the decision and use derived data: they do not rewrite what policy saw.

In practice: adding an `Authorization` header after a policy ALLOW does not change the action class, resource, or parameters that Cedar evaluated. What the audit log records is what was checked.

## Why this shape matters

The architecture gives OpenFirma a narrow job: govern outbound agent actions at the process boundary. The Sidecar does not need to understand every model, framework, prompt, or tool protocol. It needs to see the outbound request, classify it into a stable action vocabulary, validate local authority material, evaluate policy, and leave a signed audit trail.

## Where to go next

- [The enforcement pipeline](../pipeline/) explains the request path stage by stage.
- [Action classes](../action-classes/) explains how raw HTTP requests become policy vocabulary.
- [The sandbox boundary](../sandbox/) explains when `firma run` becomes relevant to the architecture.