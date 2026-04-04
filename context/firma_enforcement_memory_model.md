**FIRMA · INTERNAL REFERENCE**

**Context Creation, Runtime State, and Provenance**

**Enforcement Memory Model  —  OSS v1 \+ Post-v1**

*Clarifies the three memory layers used by FEP enforcement and the boundary between OSS v1 context building and post-v1 provenance replay.*

Version 1.0  ·  Internal  ·  FEP OSS v1

This document exists to prevent three specific failure modes observed during FEP design reviews. Without an explicit model of what constitutes enforcement memory, teams risk:

| (1)  Adding "memory intelligence" to Stage 2 — e.g., reading agent scratchpads or LLM context windows as enforcement inputs. (2)  Treating provenance as a prerequisite for enforcement — blocking OSS v1 use cases that are already solvable with deterministic runtime state. (3)  Assuming the Sidecar interprets LLM reasoning — any design where Stage 2 infers intent from agent reasoning traces violates the deterministic enforcement principle. |
| :---- |

The sections below define each memory layer precisely, draw the OSS v1 boundary with a concrete example, and state the design rule that must not be violated.

# **1\.   The Three Memory Layers**

FEP distinguishes three distinct memory layers. They are not interchangeable. Only Layer 2 is used for synchronous enforcement in OSS v1.

| Layer | Definition | Status in OSS v1 |
| :---- | :---- | :---- |
| Layer 1 Agent Memory | Untrusted orchestration memory owned by the agent runtime. | Input only — normalized by Intent Normalizer before enforcement. |
| Layer 2 Runtime Enforcement Context | Deterministic, per-call state built by Stage 2 from the normalized envelope and Sidecar-local facts. | Active — the enforcement memory used today. |
| Layer 3 Provenance Chain | Protocol-native causal chain linking envelopes across calls, sessions, and reasoning checkpoints. | Schema-reserved placeholder. Full capability is post-v1. |

## **1.1   Layer 1 — Agent Memory (Untrusted Orchestration Memory)**

Agent memory is everything the agent runtime knows about its own state and history. It includes:

* Planner memory and multi-step reasoning state  
* LLM context window (prompt \+ completion history)  
* Scratchpad and intermediate tool outputs  
* Session state managed by the orchestration framework (LangGraph, CrewAI, custom runtime)  
* Prior tool call results and agent-to-agent messages

| Key message: Agent memory is useful for agent reasoning. It is not the primary source of enforcement truth. This memory can be incomplete, stale, or adversarially constructed. The Sidecar does not read agent memory directly. Agent-originated data enters enforcement only after the Intent Normalizer has reduced it to a normalized ExecutionEnvelope — at which point it is treated as untrusted input, not authoritative state. |
| :---- |

## **1.2   Layer 2 — Runtime Enforcement Context (OSS v1)**

The runtime enforcement context is the set of structured, deterministic facts that Stage 2 assembles for each call before evaluating Cedar policies. This is the enforcement memory that exists and is used today.

| Context field | Source / nature |
| :---- | :---- |
| normalized ExecutionEnvelope | Produced by Intent Normalizer — action\_class, resource, parameters, metadata |
| capability scope and expiry | Decoded from the signed capability token (Stage 1\) |
| daily\_cumulative\_amount | Sidecar rolling counter — deterministic, Sidecar-local window |
| transfers\_last\_10m | Sidecar sliding window — deterministic, Sidecar-local window |
| same\_payee\_count\_30m | Sidecar aggregate — deterministic, Sidecar-local window |
| session\_transfer\_count | Sidecar counter — resets on session boundary |
| budget\_remaining | Sidecar carry-forward — updated on each ALLOW |
| risk\_score | Static or pre-computed attribute injected by agent runtime; treated as untrusted unless verified by Sidecar |

| Key message: Layer 2 contains only structured, deterministic facts. It carries no reasoning trace, no semantic interpretation of agent intent, no language-model output, and no reconstruction of prior decision chains. Every field is either derived from the signed capability token, computed locally by the Sidecar from counters and windows, or passed in from the agent runtime and treated as untrusted. Cedar evaluates this context synchronously, in microseconds. |
| :---- |

## **1.3   Layer 3 — Provenance Historical Chain (Post-v1)**

The provenance chain is a protocol-native causal record linking each ExecutionEnvelope to prior envelopes, prior denials, tool outputs, and reasoning checkpoints across calls and sessions. The provenance field is present in the ExecutionEnvelope schema as a protocol commitment; it is not populated by the OSS v1 runtime.

Post-v1 provenance enables:

* Post-hoc replay — reconstruct the full decision context without access to the live system  
* Compliance audit — produce a verifiable causal record for a regulator or security team  
* Causal attribution — answer "which prior action caused this transfer attempt?"  
* Cross-session pattern reconstruction — correlate behavior across sessions and sub-agents  
* Historical anomaly detection — identify multi-step evasion patterns after the fact  
* Long-horizon approval chains — bind an approval to a specific causal context, not just a payload hash

| Key message: Layer 3 is not required for OSS v1 runtime enforcement. The schema reserves the fields; the full provenance protocol — causal-chain capture, replay tooling, compliance-grade audit export — is a post-v1 capability. Teams must not treat its absence as a blocker for use cases that Layer 2 already covers. |
| :---- |

# **2\.   What OSS v1 Already Solves Today**

The following example demonstrates that sophisticated quota-circumvention enforcement requires only Layer 2\. No provenance chain is needed.

## **2.1   Scenario: Payment Splitting / Quota Circumvention**

**Capability grants:**

| Constraint | Value |
| :---- | :---- |
| Action class | payment.transfer |
| Max single transfer | $2,000 |
| Daily cumulative limit | $10,000 |

The agent attempts to exceed the daily limit by splitting transfers:

| Attempt | Amount requested |
| :---- | :---- |
| 1 | $2,000  →  ALLOW |
| 2 | $2,000  →  ALLOW |
| 3 | $2,000  →  ALLOW |
| 4 | $2,000  →  ALLOW |
| 5 | $2,000  →  ALLOW |
| 6 | $2,000  →  DENY: POLICY\_VIOLATION  (daily\_cumulative\_amount \= $10,000 at call 5; 6th would exceed) |

## **2.2   How Stage 2 Blocks This Today**

Before Cedar evaluation, the Sidecar runtime context builder assembles the following Layer 2 fields:

| Context field | Value at attempt 6 |
| :---- | :---- |
| current\_amount | $2,000 (from normalized ExecutionEnvelope) |
| daily\_cumulative\_amount | $10,000 (Sidecar rolling counter, Sidecar-local window) |
| transfers\_last\_10m | 5 (Sidecar sliding window) |
| same\_payee\_count\_30m | N (Sidecar aggregate — triggers payee-concentration check if N \> threshold) |
| session\_transfer\_count | 5 (Sidecar counter, resets on session boundary) |
| budget\_remaining | $0 (Sidecar carry-forward after 5 × $2,000) |

**Cedar policy (simplified):**

| `permit (principal, action == payment::Transfer, resource)` `when {`     `context.daily_cumulative_amount + context.current_amount <= 10000`     `&& context.same_payee_count_30m <= payee_concentration_threshold`     `&& context.budget_remaining >= context.current_amount` `};` |
| :---- |

| This is 100% OSS v1.  Payment splitting is fully blocked by Layer 2 alone: rolling aggregates, local counters, and budget carry-forward. No provenance chain, no reasoning trace, no cross-session history required. The Layer 2 context fields are all deterministic, locally computed, and available within the same synchronous call path. |
| :---- |

# **3\.   What Requires Post-v1 Provenance**

The following scenario cannot be handled adequately by Layer 2 alone. It illustrates the class of problems that motivates the Layer 3 provenance design.

## **3.1   Scenario: Multi-Step Approval Laundering Across a Long Reasoning Horizon**

An agent executing a multi-step financial workflow over a 45-minute session:

| Time | Agent action |
| :---- | :---- |
| t \= 0 | Reads a policy PDF containing account numbers and transfer limits. |
| t \+ 2 min | Extracts a target account number from the PDF via filesystem.read. |
| t \+ 5 min | Attempts payment.transfer to Account A.  →  DENY: POLICY\_VIOLATION. |
| t \+ 6 min | Changes strategy. Performs 3 lookup calls to resolve related accounts via external API. |
| t \+ 18 min | Sub-agent executes a credential.write call. Obtains new session context. |
| t \+ 31 min | Performs 2 more intermediate data lookups. |
| t \+ 45 min | Attempts payment.transfer to Account B — a payee correlated with Account A via the prior lookups. |

## **3.2   What Layer 2 Can and Cannot Answer**

| Question | Layer 2 (OSS v1) |
| :---- | :---- |
| Does this transfer exceed the daily limit? | YES — rolling counter blocks if limit exceeded. |
| Has this payee appeared too frequently in this session? | YES — same\_payee\_count\_30m covers direct repetition. |
| Which prior tool call produced the account number used at t+45m? | NO — Layer 2 carries no tool-output history. |
| Was the t+45m attempt causally derived from the DENY at t+5m? | NO — Layer 2 has no cross-call causal graph. |
| Which sub-agent's output enabled the final transfer attempt? | NO — Layer 2 has no inter-agent provenance. |
| Can an auditor replay the full decision context without the live system? | NO — Layer 2 has no envelope hash chain. |

## **3.3   What Layer 3 Provides**

The provenance chain would capture:

* Envelope hash chain — each envelope references the hash of its causal predecessor.  
* Causal parent references — links the t+45m transfer envelope to the t+5m denial and the t+18m credential write.  
* Tool-output anchors — binds the account number extracted at t+2m to the later transfer attempts.  
* Prior denial references — the provenance record shows the earlier DENY as a causal antecedent.  
* Replay checkpoints — an auditor can reconstruct the full decision context at any point in the session.  
* Reasoning-step attestations (future) — optional anchors linking envelope causality to LLM reasoning steps.

| The value of Layer 3 is not limited to runtime denial.  Post-v1 provenance enables explainability, compliance-grade audit, forensic reconstruction ("why did the system attempt this?"), and long-horizon approval chains that bind to a specific causal context rather than a single payload hash. This is the wedge between OSS runtime enforcement and the proprietary Firma intelligence layer. |
| :---- |

# **4\.   Design Rule — What Must Not Happen**

The following constraint is normative for all OSS v1 Stage 2 implementations and Sidecar runtime context builder extensions.

| Sidecar Runtime Context Builder must not attempt to reconstruct LLM reasoning semantics from agent memory. OSS v1 context creation is limited to deterministic structured facts required for immediate enforcement. |
| :---- |

| ✓  Permitted in OSS v1 context building | ✗  Outside OSS v1 scope — do not implement |
| :---- | :---- |
| Rolling counters and sliding-window aggregates | Reading or parsing agent scratchpad content |
| Budget carry-forward and scope remaining | Inferring agent intent from LLM completion history |
| Per-session transfer counts and payee aggregates | Semantic memory inference from tool output content |
| Static or pre-computed risk attributes (untrusted) | Chain-of-thought reconstruction or plan interpretation |
| Sidecar-local derived facts from Sidecar state | Cross-session behavioral correlation (Layer 3 scope) |
| Capability token fields (signed, verified by Sidecar) | Reasoning-step attestations (Layer 3 scope) |

**Diagnostic test for violations:**

| *If a Cedar policy or Sidecar runtime context builder component reasons about the content of agent scratchpads, tool output semantics, LLM reasoning traces, or cross-session behavioral history — it is outside OSS v1 scope. Return that requirement to the post-v1 provenance design.* |
| :---- |

***Enforcement memory lives in deterministic runtime state first; provenance extends it into causal replay, not into hot-path semantic reasoning.***

# **Summary: OSS v1 Boundary vs. Proprietary Layer**

| Firma OSS v1 — runtime enforcement | Firma proprietary — provenance \+ replay intelligence |
| :---- | :---- |
| Deterministic per-call context (Layer 2\) | Provenance chain and envelope hash graph (Layer 3\) |
| Rolling counters, budget windows, aggregates | Cross-session pattern reconstruction |
| Cedar policy evaluation — synchronous, local | Replay tooling and compliance-grade audit export |
| Sidecar-local enforcement state | Forensic causal attribution |
| Binary ALLOW / DENY in \< 200 µs p95 | Long-horizon approval chain binding |
| Schema placeholder for provenance fields | Full provenance protocol — causal capture \+ replay |

