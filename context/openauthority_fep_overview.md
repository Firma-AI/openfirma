OpenAuthority AI

**OpenAuthority Execution Protocol (FEP)**

Overview

**Status:** Working Draft   **|   Version:** 0.1.2   **|   Date:** April 2026

**Classification:** Internal — OpenAuthority AI Core Team

# **1\.   Purpose**

The **OpenAuthority Execution Protocol (FEP)** defines the semantic layer through which an AI agent requests, governs, and executes actions on external systems. FEP operates above the transport layer: it is agnostic to whether the underlying wire is HTTP, gRPC, or a local in-process call.

FEP achieves five properties that ad-hoc agent-to-API integrations cannot guarantee:

1. **Separation of intent from execution.**  An agent declares what it wants to do; the protocol decides whether and how it happens. Business logic never leaks into connector code.  
2. **Canonical action unit.**  Every agent action, regardless of target system, is normalised into a single structure — the **ExecutionEnvelope**. There is no per-integration action schema.  
3. **Deterministic enforcement.**  Enforcement is evaluated locally, inline, on every call. No request escapes evaluation. Synchronous execution decisions are binary: ALLOW or DENY.  
4. **Replayability.**  The envelope captures intent, capability, metadata, and provenance — the fields the protocol reserves for future replayability. Full decision reconstruction is a post-v1 capability. This is the structural precondition for audit.  
5. **Standardisation.**  New agent types, new target systems, and new enforcement policies can be added without changing the protocol. FEP is the stable interface between them.

# **2\.   Core Primitive — The ExecutionEnvelope**

The **ExecutionEnvelope** is the atomic unit of the protocol. It is created by the Sidecar Interceptor when an agent call enters the enforcement boundary, and it is immutable from that point forward. Every subsequent component — from Cedar evaluation to the Connector — operates on the same envelope.

The envelope contains four fields:

| Field | Contents |
| :---- | :---- |
| **`intent`** | `ExecutionIntent` — the normalized semantic description of the action the agent wants to perform. Contains four sub-fields: `action_class` — canonical semantic identifier for the action, defined by the Canonical Action Class Registry (e.g. `communication.external.send`, `payment.transfer`, `filesystem.delete`). Policy rules and HITL conditions bind to this field. `resource` — normalized target resource for the action. `parameters` — structured action-specific payload. `raw_transport` / `raw_action_ref` — original transport-layer identifiers, preserved for audit. These fields are observational only and must not be used for policy evaluation. |
| **`capability`** | A signed `CapabilityToken` issued by the Authority at issuance time. Encodes the permission ceiling for this session. The Sidecar verifies it at Stage 1 before any policy evaluation. |
| **`metadata`** | Execution context: session ID, agent ID, timestamp, trace ID, and budget consumed. Used for enforcement decisions, rate limiting, and audit correlation. |
| **`provenance`** | Causal chain of the action. The provenance field is a schema-reserved placeholder; the full provenance chain is a post-v1 capability. |

## **Action Types**

The protocol currently defines three action types, each with its own typed parameter block:

* **HTTP actions** (`HttpParams`) — outbound API calls: method, headers, body, query string.  
* **Database queries** (`DbQueryParams`) — named queries with typed bindings. Raw SQL is not permitted at the protocol level.  
* **Tool invocations** (`ToolUseParams`) — calls to named tools with structured input. The primary action type for LLM agents.

New action types can be added to the `oneof params` union without breaking existing implementations that do not need them.

# **3\.   Runtime Lifecycle**

Every action execution follows a fixed seven-step sequence. Steps 1–5 execute inside the Sidecar Interceptor, synchronously, before the action reaches the Connector.

6. **Agent emits a call.**  The agent produces an action request using whatever internal representation it uses (tool call, function call, intent object).  
7. **Interceptor canonicalises.**  The Sidecar Interceptor intercepts the call before it leaves the agent boundary and normalises it into an **ExecutionEnvelope**; the canonical envelope becomes the only trusted execution representation from this point forward.  
8. **Intent Normalizer classifies.**  The Sidecar Intent Normalizer maps the raw intercepted event to a canonical action class and populates the normalized `ExecutionEnvelope.intent` fields. The canonical action class and normalized resource fields are the surfaces against which Stage 2 policy evaluation and any HITL conditions are applied. The Intent Normalizer performs deterministic rule-based canonicalization — it does not perform probabilistic semantic inference, language-model reasoning, or similarity-based classification. This step makes no policy decisions. If classification fails for a protected operation, the Sidecar returns `DENY: UNCLASSIFIED_INTENT` without dispatching to a Connector.  
9. **Stage 1 — token verification.**  The Sidecar verifies the capability token: signature, expiry, and revocation status. No Cedar evaluation occurs at this stage. Target: \< 1 ms p95. A failure here produces an immediate DENY.  
10. **Stage 2 (CEE) — policy evaluation.**  The Constraint Enforcement Engine (CEE) evaluates the envelope against the active policy bundle: scope, budget, threshold conditions. Target: \< 200 µs p95. Result is ALLOW or DENY. On ALLOW, the Credential Injector derives a transport-ready execution view from the immutable ExecutionEnvelope before it exits the Sidecar.  
11. **Connector routes and adapts.**  The Connector receives the authorised envelope and translates it to the wire format required by the target system. It does not make policy decisions. It does not modify intent or capability fields.  
12. **Response and audit.**  The Connector returns a `ConnectorResponse` to the agent. Simultaneously, an audit record is emitted asynchronously to the event backend. The agent loop continues normally in either outcome.

Total end-to-end latency budget (Steps 1–4): **\< 3 ms p95** at the enforcement boundary.

# **4\.   Protocol Sections**

FEP is divided into three sub-protocols that operate across different time horizons.

## **4.1   Issuance Protocol**

The Issuance Protocol governs how a **CapabilityToken** is obtained from the Authority before execution begins. The agent or orchestrator calls `AuthorityService.IssueCapability` with an `IssueCapabilityRequest` describing the session, the agent, and the requested scope.

The Authority evaluates the request against its policy and returns a signed token. The token encodes the **permission ceiling** for the session: what the agent is permitted to do. The Sidecar can only enforce within this ceiling — it cannot elevate permissions that the Authority did not grant.

The Authority is never on the hot path. Once the token is issued, the Sidecar operates independently. Policy updates and revocation events are streamed to the Sidecar via `WatchPolicyBundle` and `WatchRevocations` — the Sidecar does not call back to the Authority per execution.

## **4.2   Execution Protocol**

The Execution Protocol is the core of FEP. It covers the full lifecycle of a single action: from the agent call, through Interceptor canonicalisation, Stage 1 verification, Stage 2 policy evaluation, credential injection, Connector routing, and response return.

The Execution Protocol is **synchronous** from the agent's perspective. The agent makes a call and receives a result. Whether the result is a successful response or a DENY signal, it is always delivered as a structured value — never as a hard crash. This is critical for tool-use agents, where a DENY must be surfaced as tool output, not as an exception that breaks the agent loop (see Section 5).

The Sidecar maintains a local copy of the policy bundle and revocation state. It **never** calls the Authority inline. All runtime decisions are local.

## **4.3   Provenance Protocol**

The Provenance Protocol defines how the causal chain of an action is captured and preserved. A **provenance record** answers the question: why did the agent make this call? Which prior reasoning step, instruction, or agent output caused this particular action to be emitted?

A complete provenance chain enables **post-hoc replay**: given the envelope and its provenance, an external auditor can reconstruct the full decision context without access to the live system.

**OSS v1 scope note:**  The provenance field is a schema-reserved placeholder in v1 — present in the ExecutionEnvelope schema as a protocol commitment, but not populated by the runtime. The full Provenance Protocol — causal-chain capture, replay tooling, and compliance-grade audit export — is a post-v1 capability and is not included in the OSS release.

# **5\.   DENY Semantics**

A DENY in FEP is not a single uniform event. The Sidecar must distinguish between two structurally different denial contexts and handle them differently to preserve the behaviour the agent and its orchestrator expect.

## **5.1   Tool Denial**

When the denied action is a **tool call** — an invocation of a named tool from within an LLM agent loop — the DENY must not terminate the agent session. The agent loop is a reading loop: it reads tool results and continues reasoning. A hard error at the tool boundary breaks that loop.

In a tool denial, the Sidecar returns a **structured tool output** that represents the denial: a machine-readable result indicating the tool call was not permitted. The agent receives this output exactly as it would receive any other tool result, and can reason about it, log it, or escalate it. The agent session continues.

The denial record is emitted asynchronously to the event backend regardless. The agent loop remains intact.

## **5.2   API Denial**

When the denied action is a direct **API call** — HTTP, database query, or any non-tool connector invocation — the Sidecar returns a hard block. The call does not reach the target system. The response to the caller is an explicit authorization failure.

API denials are synchronous and terminal for that call. Unlike tool denials, there is no expectation that the caller will recover transparently: an API denial signals that the action is outside the permission boundary, and the caller must handle it explicitly.

## **5.3   ABORT Signals**

ABORT is structurally distinct from DENY. It is not a pre-call decision: it is an **in-flight kill signal** issued asynchronously while an action is already executing. The Authority or an operator emits an ABORT when a session or capability must be terminated mid-flight — for example, in response to a revocation event or a policy threshold breach detected out-of-band.

The Sidecar receives ABORT signals via the `WatchRevocations` stream and terminates any in-progress execution associated with the revoked capability. ABORT is not surfaced as a standard EnforcementDecision value — it operates on a different axis from ALLOW/DENY.

# **6\.   Connector Boundary**

The **Connector** is the protocol adapter between the enforcement layer and the target system. Its role is precise and bounded. Understanding what the Connector may and must not do is essential to implementing compliant integrations.

By the time a request reaches the Connector, semantic classification is already complete. The Connector receives a normalized `ExecutionEnvelope` — it does not perform and must not perform first-time intent classification.

## **6.1   What the Connector may do**

* Translate the `ExecutionEnvelope` into the wire format of the target system (HTTP request, SQL call, tool invocation payload, etc.).  
* **Apply technical constraints**: connection pooling, retry policy, timeout enforcement, rate limiting that reflects target-system limits (not business policy).  
* Inject the credentials that the Credential Injector placed into the envelope after Stage 2 ALLOW. The Connector reads these credentials — it does not generate or validate them.  
* Return a `ConnectorResponse` to the Sidecar, which relays it to the agent.

## **6.2   What the Connector must not do**

* **Make authorization decisions.**  The Connector receives an already-authorised envelope. It has no access to the capability token, policy bundle, or Cedar engine. It must not apply additional policy gates or conditionally suppress actions.  
* **Modify intent or capability fields.**  The envelope is immutable from the point the Interceptor creates it. The Connector must not alter the intent, rewrite parameters, or modify the capability token.  
* **Implement business logic.**  Routing logic, approval flows, scope transformations, or any decision that depends on the content of the request — not its technical delivery — belongs in the policy layer, not the Connector.  
* **Source credentials independently.**  Credentials are injected by the Credential Injector at the Sidecar level, after authorization. The Connector does not fetch, cache, or validate credentials from external systems.

The Connector boundary is the clearest separation of concerns in the protocol. Violation of these rules does not produce immediate errors — it produces **silent, untraceable policy bypass**. Connector implementations must be reviewed against this boundary at every change.

# **7\.   Canonical Action Class Registry**

FEP defines a stable set of **canonical action classes** — semantic identifiers that appear in `ExecutionEnvelope.intent.action_class`. Their purpose is to ensure that semantically equivalent actions are represented identically regardless of transport, connector, or runtime-specific implementation.

Policy rules, HITL conditions, and audit classification bind to registry-defined action classes, not to transport-specific names. The registry is part of the semantic protocol surface.

Key properties:

* FEP defines a fixed set of canonical action classes. In v0.1 the registry is a bounded configuration-time enum — runtime extension is not permitted.  
* Policy rules and HITL conditions must bind to registry identifiers, not to transport-specific names such as tool names, HTTP methods, or CLI commands.  
* If the Intent Normalizer cannot deterministically classify a protected action to a registry entry, the Sidecar returns `DENY: UNCLASSIFIED_INTENT` and no Connector dispatch occurs.

Examples of registry-defined action classes: `communication.external.send`, `payment.transfer`, `filesystem.delete`, `credential.write`, `system.execute`. See FEP Specification §2.3 for the complete registry definition, naming rules, and versioning policy. Registry identifiers are versioned with the semantic protocol and remain stable across compatible revisions.

# **8\.   Protocol Scope**

FEP is an **L7 semantic protocol**. It operates at the application meaning layer — the layer of intent, authorization, and action semantics. It is explicitly **not** a transport protocol.

* FEP does not mandate a wire format. The current implementation uses gRPC between the agent and the Authority, and an in-process call between the Sidecar and the Connector. Either can change without changing FEP.  
* FEP does not mandate an agent architecture. It is compatible with single-agent, multi-agent, and orchestrator-worker topologies. The Sidecar is deployed per agent, but the protocol is the same across all deployments.  
* FEP does not mandate a policy language. Cedar is the current implementation of the CEE. The protocol requires a binary ALLOW/DENY decision — it does not require Cedar specifically.  
* FEP does not include transport security. TLS, mTLS, and network-level access controls are infrastructure concerns. FEP assumes the transport is authenticated by infrastructure or upstream identity systems — it does not provide or verify it.

FEP can be adopted incrementally. An existing integration that calls APIs directly can be brought under FEP by inserting a Sidecar Interceptor at the boundary and wrapping calls in an ExecutionEnvelope. The target system does not need to be modified.

**Appendix A — Key Terms**

| Term | Definition |
| :---- | :---- |
| **`ExecutionEnvelope`** | The canonical, immutable unit of a single agent action. Contains intent, capability, metadata, and provenance. |
| **`Sidecar Interceptor`** | The local enforcement component that canonicalises agent calls, runs Stage 1 and Stage 2, and injects credentials before routing to the Connector. |
| **`Stage 1`** | Token verification: signature, expiry, revocation check. No policy evaluation. Target \< 1 ms p95. |
| **`CEE / Stage 2`** | Constraint Enforcement Engine: executes Cedar policy evaluation and quantitative runtime constraints (budget, scope, thresholds) against the active policy bundle. Target \< 200 µs p95. |
| **`Credential Injector`** | Derives a transport-ready execution view from the immutable ExecutionEnvelope after Stage 2 ALLOW, injecting credentials before the envelope reaches the Connector. |
| **`Connector`** | Protocol adapter. Translates the envelope to the target-system wire format. Makes no policy decisions. |
| **Intent Normalizer** | Deterministic Sidecar component that canonicalizes bounded raw runtime events into registry-defined action classes and normalized resources before Stage 1 and Stage 2\. Performs rule-based canonicalization only. No language model, SLM, or probabilistic classifier is permitted on the hot path. |
| **`CapabilityToken`** | Signed token issued by the Authority. Encodes the permission ceiling for a session. |
| **`Authority`** | The issuance-time component. Issues capability tokens and streams policy/revocation updates. Never on the hot path. |
| **`ALLOW / DENY`** | Synchronous binary enforcement decision produced by Stage 2 (CEE). |
| **`ABORT`** | Asynchronous in-flight kill signal. Structurally distinct from DENY — not a pre-call decision. |
| **`Permission Ceiling`** | The maximum permissions the Authority granted. The Sidecar enforces within it but cannot exceed it. |
| **`FEP`** | OpenAuthority Execution Protocol. The semantic L7 protocol defined in this document. |

**Appendix B — OSS v1 Scope Boundary**

The following capabilities are defined in FEP but are not implemented in the OSS v1 release:

* Provenance chain capture and replay tooling.  
* Compliance-grade audit export backend (OpenAuthority Chain).  
* Multi-tenant control plane.  
* Dynamic risk engine and trust graph.  
* Cedar policy compiler and management UI.  
* Escalation engine.  
* Enterprise memory governance.

These capabilities are architectural commitments — they are reflected in the protocol schema and the component interfaces — but they are not activated in the OSS build. See the **OpenAuthority AI OSS Component Reference**, Section 13, for the complete V1 scope boundary.