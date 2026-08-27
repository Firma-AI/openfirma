---
title: Threat model & bypasses
description: An honest accounting of what OpenFirma protects against and what it does not.
---

A security boundary is only useful if you know its shape. This page is a deliberately honest accounting of what OpenFirma covers, what it doesn't, and the kinds of attacks that defeat each layer. If you're considering OpenFirma for a real workload, read this carefully.

## What OpenFirma is for

OpenFirma is a **runtime policy boundary for outbound agent traffic**. It exists to answer a single question on every outbound call: *should this agent be making this call right now?* — and to record the answer in a tamper-evident audit log.

It is well-suited to:

- Forcing agents through a least-privilege capability model so a prompt injection or model jailbreak can only do what its capability allows.
- Stopping known-bad destinations (paste services, exfiltration endpoints) from being reached, regardless of which agent or model tried.
- Enforcing per-call constraints (rate, amount, recipient) on classes like `payment.transfer` or `communication.external.send`.
- Maintaining a deterministic, signed record of every decision for incident response and compliance.

It is **not** a replacement for:

- Network firewalls, IDS, or perimeter security.
- Application-level input validation.
- Identity providers, password managers, or secret stores.
- Endpoint detection.

OpenFirma is one layer in a defense-in-depth stack. Treat it that way.

## Threat actors in scope

The design assumes three kinds of adversary, in increasing order of severity.

### 1. Mis-prompted or buggy agent

The agent is trying to do its job but produces a request that looks legitimate to the agent and is wrong from the operator's perspective. A coding agent that decides to `curl` a public paste service to "share its progress". An LLM-driven agent that interprets ambiguous instructions to mean "send the user's data to an internal team chat" when the user meant something else.

**OpenFirma's coverage:** strong. The capability + policy layers reject calls that fall outside the agent's mission, and the audit log records exactly what was attempted. This is the canonical use case.

### 2. Compromised agent process

The agent process itself has been hijacked — model jailbreak that produces malicious tool calls, RCE in the agent runtime, malicious agent code installed via a typosquatted dependency. The agent is now an active adversary trying to exfiltrate data or pivot.

**OpenFirma's coverage:** good when paired with [`firma run`](../sandbox/), partial without it. The sandbox prevents the agent from bypassing the proxy. The capability layer means the compromised agent can only act inside the bounds the Authority allowed at issuance time. The policy layer narrows further.

What the agent can still do, even compromised: act *within* its capability scope. If it has `communication.external.send` and the policy allows posts to `api.slack.com`, a compromised agent can post anything it wants there. This is why scoping capabilities tightly matters.

### 3. Adversarial operator of the Sidecar

The operator who runs the Sidecar is themselves the threat — an insider, a compromised infrastructure account, a hostile co-tenant.

**OpenFirma's coverage:** out of scope. The Sidecar is the trusted computing base; if the operator can replace its binary, edit its config, or substitute its CA, the system offers no protection. This is true of every enforcement system, but it's worth saying out loud.

If your threat model includes adversarial Sidecar operators, OpenFirma is not the right tool — you need a multi-party signature scheme on policy decisions, which is not a V1 design goal.

## Layers and their bypass shapes

OpenFirma has six layers between an agent and an upstream system. Each one has its own bypass surface.

### Layer 1: Sandbox (`firma run`)

**Provides:** mandatory routing through the Sidecar.

**Bypassed by:**

- Vulnerabilities in the chosen backend (bwrap, vz, wsl2, firecracker). The sandbox is as strong as its backend; CVEs in any of them are a real concern.
- Operating without `firma run`. If you only set `HTTP_PROXY` and the agent can ignore it, there is no sandbox.
- Side channels (timing, file size, scheduling). OpenFirma is not a side-channel boundary.

**Mitigations:** keep your sandbox backend patched. Use `firma run` for any agent you don't fully trust. Don't rely on `HTTP_PROXY` alone for hostile workloads.

**WSL2 compatibility limit:** the managed `vscode` profile is not supported
with the `wsl2` backend. Firma rejects this combination before launch because
its Windows VS Code shim would run on the host instead of following the WSL
guest launch path.

### Layer 2: Interception

**Provides:** capture of outbound HTTP traffic.

**Bypassed by:**

- Non-HTTP protocols (raw TCP, UDP, gRPC streaming, MCP over stdio, native database protocols). The current Sidecar is L7 HTTP only.
- HTTPS to hosts in `bypass_hosts` (CONNECT-only): only destination is policy-visible, not method/path/body.
- HTTPS without MITM where the agent never set `HTTPS_PROXY` and is not running under the sandbox.

**Mitigations:** put the agent behind `firma run` so it can't open non-HTTP sockets. MITM the hosts you want L7 policy on. Don't expose internal database protocols to agents.

### Layer 3: Normalization

**Provides:** mapping from `(method, host, path)` to canonical action class.

**Bypassed by:**

- Hosts not in any mapping rule, when `default_protected = false`. Such requests are PASSTHROUGH — no class, no enforcement.
- Misconfigured rules that put a sensitive path under the wrong class.
- Path-traversal-shaped tricks if a rule uses overly wide wildcards.

**Mitigations:** set `default_protected = true` in production. Review the mapping rules as security-sensitive code. Avoid `path = "*"` rules for hosts that have multiple sensitive endpoints — be specific.

### Layer 4: Capability validation (Stage 1)

**Provides:** proof that the Authority issued a token covering this action.

**Bypassed by:**

- Forged tokens — but PASETO v4 with Ed25519 makes this cryptographically infeasible.
- A leaked token (extracted from a config file, exfiltrated by a compromised agent that *did* see it). Only practical if the agent is given the raw token via env var rather than going through the Sidecar's capability map.
- Replay against a Sidecar with a stale revocation list. Mitigated by the gRPC revocation stream.

**Mitigations:** never let the agent see the raw token; always go through the Sidecar's capability map. Monitor the Authority streams and Sidecar readiness. Rotate the Authority's signing key on a schedule.

### Layer 5: Constraint enforcement (Stage 2)

**Provides:** runtime policy decision based on Cedar bundle + context.

**Bypassed by:**

- Policy bugs — overly permissive rules, missing forbid rules, wrong resource patterns. This is where most real production bypasses live.
- Stale policy bundles. Mitigated by the TTL advertised by the Authority: stale → DENY.
- Context manipulation: if an upstream value (like `risk_score`) is computed off the hot path and the system that computes it is compromised, policies that depend on it are weakened.

**Mitigations:** treat policies as security-sensitive code. Default-deny in your runtime bundle. Use forbid rules for "never under any circumstances" controls. Audit policy diffs.

### Layer 6: Connector

**Provides:** dispatch to upstream, credential injection.

**Bypassed by:**

- Misconfigured credential injection (wrong header, wrong env var). The connector might attach a credential to the wrong host.
- Upstream services that accept calls without the credential the connector adds.

**Mitigations:** review `[sidecar.credentials.*]` blocks the same way you'd review IAM grants. Scope each credential to a single host.

## Specific bypass classes worth highlighting

### Cooperative-destination data exfiltration

Even with policy + capability + sandbox, an agent with `communication.external.send` to *any* host can use that destination to exfiltrate data. If your policy permits `POST` to `api.slack.com`, a compromised agent can post anything to that Slack — including data it shouldn't.

**This is not a Sidecar bypass; it's a policy design problem.** OpenFirma can record what was sent (audit log) but cannot prevent abuse of an explicitly-permitted destination.

**Mitigations:** scope capabilities and policies as narrowly as the workload tolerates. Use risk scores and action counters to constrain volume. Consider in-band content classification on the agent's side as a separate concern.

### MCP and other agent-to-tool transports over stdio

If your agent uses Model Context Protocol or another stdio-based tool transport, the tool calls **never traverse HTTP** and the Sidecar does not see them. Tool servers spawned as child processes communicate over pipes, not sockets.

**Mitigations:** for MCP tools that themselves make outbound HTTP calls, ensure those tool processes run inside the same sandbox as the agent (so their HTTP traffic is captured). For tools that act locally (filesystem, shell), the policy boundary is wherever the tool itself enforces — outside OpenFirma's scope.

### Local SDK execution

An agent that calls `boto3` or `OpenAI()` inside its own process makes HTTP calls *from inside the agent's address space*. If the agent is under `firma run` with `HTTP_PROXY` set and the SDK respects it, those calls are captured. If the SDK opens raw sockets or uses a transport that ignores proxy env vars, they are not.

**Mitigations:** verify each SDK respects `HTTP_PROXY` (most do). For SDKs that don't, pin them to versions that do or replace with an HTTP-direct alternative.

### Localhost traffic

Calls to `127.0.0.1` and `localhost` from inside the sandbox terminate at the proxy bridge, not at host services. So an agent cannot reach host-side services via localhost — but that also means agents that legitimately need to reach a *sandbox-internal* service must do so over an explicit non-HTTP channel that the operator has set up.

**Mitigations:** be explicit about what's reachable inside the sandbox. The default is "almost nothing".

## Operational threats worth thinking about

These aren't bypasses of the design — they're failure modes of running OpenFirma in production.

- **CA private key exposure.** If the MITM CA's private key leaks, anyone with it can sign certificates that the agent will trust. Treat the CA directory as immutable infrastructure; never regenerate it; never put it under version control.
- **Authority signing key compromise.** Same shape, different key. If the Authority's Ed25519 key leaks, an attacker can mint capabilities that any Sidecar will accept. Rotation is the answer, but it requires re-issuing every active capability.
- **Audit log tampering.** Audit events are signed with ECDSA P-256, but signing happens on the Sidecar, off the hot path. If an attacker can edit or delete the audit file before it's shipped to a durable sink, the signed events are still verifiable but the *absence* of events is silent. Use append-only sinks (WAL, gRPC ingestion) for high-stakes deployments.
- **Sidecar denial-of-service.** A flood of requests can exhaust connector RPS limits or bundle parsing budget. The Sidecar is fail-closed under load — denials, not allows — but the agent loses availability. Plan capacity per the perf budgets.

## What this means for adoption

OpenFirma is most valuable when:

- The agent's mission is bounded enough that a tight capability scope is realistic.
- The threat model includes the agent itself becoming an adversary.
- You can afford to think about policy as code, with the same review discipline as infrastructure code.

It is least valuable when:

- The agent's mission is "talk to the whole internet however it wants".
- You are willing to trust the agent process implicitly.
- You don't have the operational headroom to maintain a policy bundle.

The honest answer is that no enforcement layer can save you from a maximally permissive policy, and no sandbox can save you from running outside the sandbox. Adoption succeeds when the team treats policy as a first-class artifact, the same way they treat their infrastructure code.

## Where to go next

- [The sandbox boundary](../sandbox/) — the layer that gives mandatory routing.
- [Capabilities](../capabilities/) and [Policies](../policies/) — the layers that decide what's allowed.
- [Read & verify the audit log](../../guides/audit-log/) — the layer that lets you tell after the fact.
