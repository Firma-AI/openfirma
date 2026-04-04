Firma AI

**Firma Execution Protocol (FEP)**

Specification v0.1.2

**Status:** Semantic draft — wire format not frozen   **Version:** 0.1.2  **Date:** April 2026

**Authors:** Firma AI Core Team   **Companion:** firma\_fep\_overview.docx

# **1\.   Purpose and Scope**

The **Firma Execution Protocol (FEP)** is the semantic L7 protocol governing how AI agents request, govern, and execute actions on external systems. FEP operates at the application meaning layer — above transport, above wire serialisation, above RPC mechanics. It defines what a protocol-compliant action **means**, not how it is transmitted.

The FEP protobuf contracts (`firma/v1/types.proto`, `firma/v1/authority.proto`) define the wire format and RPC surface. They are a necessary implementation of this specification, not the specification itself. Where the two diverge, this document is the source of truth for semantic behaviour. A protobuf implementation that passes schema validation but violates the invariants in §3 is non-conformant.

This specification defines: the canonical protocol unit (**ExecutionEnvelope**); the semantic invariants all implementations must satisfy; the lifecycle of the three sub-protocols (Issuance, Execution, Provenance); the decision semantics for ALLOW, DENY, and ABORT; and the boundary rules for Authority, Sidecar, and Connector components. It does **not** define transport security, primary identity, or policy authoring.

# **2\.   Protocol Primitive — ExecutionEnvelope**

The **ExecutionEnvelope** is the atomic unit of the FEP. Every action an agent can perform must be represented as an envelope before it enters the enforcement boundary. The envelope is created by the Sidecar Interceptor at the point of canonicalisation and is immutable thereafter.

The envelope encodes four semantic roles:

* **intent** — normalized description of the attempted action. Sub-fields: action\_class (canonical semantic action class), resource (normalized target resource identifier), parameters (action-specific parameters or parameter hashes), raw\_transport (original transport form, e.g. exec, http, grpc, tool — observational only), raw\_action\_ref (original tool name / route / method — observational only). Stage 2 policy rules must bind to action\_class and resource; binding to raw\_transport or raw\_action\_ref is a non-conformant configuration.  
* **capability** — the permission ceiling that authorises the intent: a signed CapabilityToken issued by the Authority at issuance time. The Sidecar verifies this field; it does not generate or modify it.  
* **metadata** — the operational context needed for enforcement evaluation and audit correlation: session ID, agent ID, timestamp, trace ID, budget consumed. Populated by the Sidecar and agent runtime.  
* **provenance** — the causal chain that produced this action. Reserved in v0.1; see §5.3.

| Field | Semantic role | Required? | Mutable after creation? | Source |
| :---- | :---- | :---- | :---- | :---- |
| `intent` | Attempted action | Yes | No | Interceptor |
| `capability` | Permission ceiling | Yes | No | Authority |
| `metadata` | Execution context | Yes | No | Sidecar / agent |
| `provenance` | Causal chain *(reserved)* | Reserved | No | Future |

## **2.1   Action Types**

The `intent` field carries a typed `oneof params` variant. Three action types are defined in v0.1:

* `HttpParams` — outbound HTTP/S calls. Carries method, headers, body, query string. Raw URL construction is performed by the Connector, not the agent.  
* `DbQueryParams` — named database queries with typed bindings. Raw SQL strings are not permitted at the protocol level.  
* `ToolUseParams` — named tool invocations with structured input. Primary action type for LLM-driven agents.

Additional action types may be added to the `oneof` union in future versions without breaking implementations that do not reference them.

## **2.2   Intent Normalization and Canonical Action Class**

**Intent Normalization.** Deterministic canonicalization process that maps a bounded raw intercepted runtime event surface (tool call, typed exec wrapper, HTTP request, browser action, etc.) into a canonical action class and normalized resource fields. This step performs rule-based canonicalization only — it does not perform probabilistic semantic inference, language-model reasoning, or similarity-based classification. Canonical semantic meaning does not imply probabilistic interpretation. In FEP v0.1, no language model, SLM, or probabilistic classifier is permitted on the hot path.

Intent normalization is not a policy decision. Its purpose is to ensure that actions with the same canonical meaning are represented identically in the `ExecutionEnvelope` regardless of transport or runtime-specific implementation. Intent normalization occurs in the Sidecar hot path before Stage 1 and Stage 2\. If normalization fails or yields an ambiguous action class for a protected operation, the Sidecar returns DENY: UNCLASSIFIED\_INTENT and no Connector dispatch occurs.

**Canonical Action Class.** The normalized semantic action type in intent.action\_class. Examples: `communication.external.send`, `payment.transfer`, `filesystem.delete`, `credential.write`. The v0.1 taxonomy is a bounded configuration-time enum; runtime extension is not permitted in v0.1.

**Cross-transport normalization example.** The following raw events must all normalize to the same canonical action class `communication.external.send`: a native tool email.send, a CLI exec gmail send ..., an HTTP POST to a mail microservice, and an MCP mail tool invocation. Policies and HITL approvals must bind to the canonical action class, not to any transport-specific name.

## **2.3   Canonical Action Class Registry**

**Canonical Action Class Registry.** The Canonical Action Class Registry defines the stable semantic identifiers that may appear in `ExecutionEnvelope.intent.action_class`. Its purpose is to ensure that semantically equivalent actions normalize to the same identifier regardless of transport, connector, or runtime-specific representation.

The registry is part of the semantic protocol surface. Policy rules, HITL conditions, audit classification, and capability issuance scope must bind to registry-defined action classes rather than transport-specific names.

### **2.3.1   Registry properties**

The registry satisfies the following properties:

* **Stable identifiers.** Action class identifiers are versioned semantic names and must remain stable across compatible protocol revisions.  
* **Transport independence.** An action class describes the meaning of an action, not its transport, connector, or tool implementation.  
* **Deterministic mapping target.** Intent Normalizers must map raw runtime events to registry-defined action classes.  
* **Policy surface.** Stage 2 policy evaluation must bind to action classes from this registry.  
* **Audit surface.** Audit events must record the normalized action class.  
* **Issuance compatibility.** Capability scopes may reference action classes from this registry as part of the permission ceiling.  
* **Deterministic registry mapping.** For any protected raw event within the supported v0.1 surface, normalization must yield the same canonical action class under identical input conditions. This property makes Intent Normalization behavior deterministic, testable, and reproducible across conformant implementations.

### **2.3.2   Naming rules**

Registry identifiers follow a dotted lowercase namespace form: `<domain>.<subdomain>.<verb>`.

Examples:

* `communication.external.send`  
* `payment.transfer`  
* `filesystem.delete`  
* `credential.write`

Naming rules:

* identifiers must be lowercase ASCII with dot separators;  
* identifiers must describe semantic meaning, not implementation details;  
* provider names, transport names, and connector names must not appear unless the semantic meaning truly depends on them;  
* identifiers must be concise, stable, and human-readable.

Non-conformant examples:

* `gmail.send` — encodes provider name  
* `http.post.mail` — encodes transport  
* `exec_gmail_send` — encodes transport and provider  
* `tool.email.send` — encodes implementation layer  
* `telegram.exec` — encodes transport channel and execution method, not semantic action  
* `exec.telegram_send` — encodes execution method and transport channel, not semantic action

These encode transport or implementation, not semantic meaning.

### **2.3.3   Registry conformance rules**

An action is **protected** if its semantic type falls within the registry scope. Actions outside the v0.1 protected registry scope are not automatically permitted. An implementation must either explicitly permit-list them as low-risk transport-preserving operations requiring no semantic classification, or treat them as unclassified protected operations and return DENY: UNCLASSIFIED\_INTENT. The default posture for unknown actions must be fail-closed.

The following conformance rules apply to all protected actions:

* Intent Normalization must map each protected action to exactly one registry-defined action class.  
* If multiple transports produce the same semantic action, they must map to the same action class.  
* If no deterministic mapping is possible for a protected operation, the Sidecar must return DENY: UNCLASSIFIED\_INTENT.  
* Runtime extension of the registry is not permitted in v0.1. Implementations may only use action classes defined by the configured v0.1 registry.  
* Deprecated action classes may remain accepted for backward compatibility, but new policy authoring must use the current canonical identifier.

### **2.3.4   Relationship to typed parameters**

`intent.action_class` expresses the semantic meaning of the action. The typed params variant expresses the structured payload shape for that action. These are distinct:

* **action class** — what the action means  
* **params type** — how the action payload is structured

Example:

* `action_class` \= `communication.external.send`  
* params may be represented through `ToolUseParams` in one runtime or another future params family in a later revision

The action class remains stable even when the transport or parameter schema family changes.

### **2.3.5   Initial v0.1 registry**

The following action classes are defined in v0.1. The registry is a bounded configuration-time enum; runtime extension is not permitted.

**Communication**

* `communication.external.send`  
* `communication.internal.send`

**Payments**

* `payment.transfer`  
* `payment.purchase`

**Filesystem**

* `filesystem.read`  
* `filesystem.write`  
* `filesystem.delete`

**Credentials and permissions**

* `credential.read`  
* `credential.write`  
* `account.permission.change`

**System**

* `system.install`  
* `system.execute`

**Browser**

* `browser.purchase`

**Memory**

* `memory.cross_namespace.read`  
* `memory.cross_namespace.write`

The following classes are reserved for a future minor revision and must not be used in v0.1 policy authoring: `memory.read`, `memory.write` (intra-namespace memory operations are not in the v0.1 policy surface); `browser.navigate` (high classification volume relative to risk signal at v0.1 scope).

### **2.3.6   Cross-transport examples**

The following raw events must normalize to `communication.external.send`:

* native tool email.send  
* CLI exec gmail send …  
* HTTP POST to a mail microservice  
* MCP mail tool invocation  
* Telegram message send via exec tool

The following raw events must normalize to `system.execute`:

* exec tool call  
* shell command  
* subprocess invocation  
* bash tool call  
* script runner invocation

**system.execute** is a bounded high-risk fallback semantic class for raw execution surfaces whose business meaning cannot be deterministically elevated into a narrower canonical action class. Implementations must not use `system.execute` as a convenience class for actions that can be classified more specifically.

The following raw events must normalize to `system.install`:

* pip install …  
* npm install …  
* package manager plugin install  
* runtime dependency add command

The following raw events must normalize to `filesystem.delete`:

* file delete tool call  
* shell rm  
* API delete request against a file service  
* recursive workspace removal helper

### **2.3.7   Versioning policy**

The Canonical Action Class Registry is versioned with the semantic protocol. Compatibility rules:

* existing identifiers must not be renamed in a compatible revision;  
* new identifiers may be added in minor revisions;  
* identifiers may be deprecated but must not be silently repurposed;  
* removal requires a major protocol revision.

**v0.1 clarification on intent.** Stage 2 policy evaluation must be written against normalized action classes and normalized resources, not transport-specific tool names, unless explicitly intended for low-level technical controls with no semantic policy implications.

# **3\.   Protocol Invariants**

The following invariants are normative. An implementation that violates any of them is non-conformant with FEP v0.1, regardless of whether it passes protobuf schema validation. Invariants are grouped by concern.

## **3.1   Envelope Invariants**

1. **\[I-E1\]**  The ExecutionEnvelope is the atomic unit of the protocol. Every agent action that crosses the enforcement boundary must be represented as an envelope.  
2. **\[I-E2\]**  Once canonicalised by the Interceptor, the envelope is the only trusted execution representation. No component may revert to or act on the original agent call.  
3. **\[I-E3\]**  The envelope is immutable after creation. No component downstream of the Interceptor may alter the `intent`, `capability`, or `metadata` fields.

## **3.2   Authority and Permission Invariants**

4. **\[I-A1\]**  The Sidecar cannot extend the permission perimeter defined by the Authority. The capability token is a ceiling, not a floor.  
5. **\[I-A2\]**  The Authority is never on the hot path. All runtime enforcement decisions are local to the Sidecar. No action evaluation requires a synchronous call to the Authority.  
6. **\[I-A3\]**  Policy bundle and revocation state are streamed to the Sidecar at subscribe time. The Sidecar uses its local copy at eval time.

## **3.3   Enforcement Invariants**

7. **\[I-F1\]**  Every action that reaches the Connector has passed Stage 1 and Stage 2 evaluation. There is no bypass path.  
8. **\[I-F2\]**  Stage 1 (token verification) and Stage 2 (policy evaluation) are both local operations. Neither requires a network call.  
9. **\[I-F3\]**  Credential injection occurs after Stage 2 ALLOW and before the envelope reaches the Connector. The Connector does not source credentials independently.  
10. **\[I-N1\]**  Stage 2 policy rules must evaluate against the normalized `intent.action_class` and `intent.resource` fields, not against transport-specific fields (`raw_transport`, `raw_action_ref`). Policies that bind enforcement to transport-specific fields are non-conformant unless explicitly scoped to low-level technical controls with no semantic policy implications.

## **3.4   Connector Invariants**

11. **\[I-C1\]**  The Connector does not make authorisation decisions. It receives an already-authorised envelope and performs translation only.  
12. **\[I-C2\]**  The Connector does not implement business logic. Scope transforms, approval conditions, and routing policy belong in the Cedar evaluation layer.

## **3.5   Decision Invariants**

13. **\[I-D1\]**  Synchronous enforcement decisions are binary: ALLOW or DENY. There is no partial allow.  
14. **\[I-D2\]**  ABORT is not a synchronous enforcement decision. It is an asynchronous in-flight termination signal and operates on a separate axis from ALLOW/DENY (see §6).  
15. **\[I-D3\]**  A tool denial (DENY on a tool call) must not terminate the agent session. It must be surfaced as a structured tool result so the agent loop continues.

# **4\.   Issuance Protocol**

The Issuance Protocol governs how a CapabilityToken is obtained from the Authority before execution begins. It operates entirely outside the hot path.

## **4.1   RPC Operations**

| Operation | Type | Semantic role |
| :---- | :---- | :---- |
| `IssueCapability` | Unary | Request a signed CapabilityToken for a session. Authority evaluates scope and returns a token or rejection. |
| `WatchPolicyBundle` | Server-stream | Stream policy bundle updates to the Sidecar. Sidecar applies updates to its local eval state without restarting. |
| `WatchRevocations` | Server-stream | Stream revocation events. Sidecar marks affected tokens as invalid; triggers ABORT for in-progress executions. |

## **4.2   IssueCapability Semantics**

**Input:** session identity, agent identity, requested scope, and any context the Authority needs to evaluate the request (environment, workload claims, etc.).

**Output:** a signed CapabilityToken encoding the **permission ceiling** for the session — the maximum set of actions the Sidecar may allow. The token does not guarantee that any specific action will be allowed; it constrains the space within which the Sidecar evaluates.

The Authority makes a **can this capability exist?** decision. The Sidecar subsequently makes the **can this specific call happen right now?** decision. These are distinct evaluations with distinct inputs and timing.

**v0.1 scope:**  The IssueCapability response in v0.1 uses a bool \+ optional token pattern. A future revision should replace this with a typed oneof result (token | rejection\_reason) to eliminate the invalid state (granted=false with a token present).

## **4.3   Authority Off-Path Guarantee**

Once a token is issued and the policy/revocation streams are active, the Authority makes no further contribution to individual action decisions. The Sidecar operates independently. Loss of connectivity to the Authority does not block in-progress execution (until existing tokens expire or are revoked via the stream).

# **5\.   Execution Protocol**

The Execution Protocol defines the hot-path lifecycle of a single agent action. All steps from canonicalisation through audit are synchronous from the agent's perspective, except the final audit emission.

## **5.1   Hot-Path Sequence**

| Step | Component | Operation | Latency target |
| :---- | :---- | :---- | :---- |
| 1 | Sidecar Interceptor | Receive agent call; canonicalise into ExecutionEnvelope. | — |
| 1.1 | Sidecar — Intent Normalizer / Envelope Builder | Classify raw intercepted event into canonical action\_class; populate intent sub-fields (action\_class, resource, parameters, raw\_transport, raw\_action\_ref). Returns DENY: UNCLASSIFIED\_INTENT on classification failure. Must not make policy decisions. | — |
| 2 | Sidecar — Stage 1 | Verify CapabilityToken: signature, expiry, revocation status. | \< 1 ms p95 |
| 3 | Sidecar — Stage 2 | Cedar evaluation: scope, budget, threshold conditions. → ALLOW or DENY. | \< 200 µs p95 |
| 4 | Credential Injector | On ALLOW: inject execution credentials into envelope. | — |
| 5 | Connector | Translate envelope to target-system wire format; dispatch call. | — |
| 6 | Audit | Emit audit record asynchronously. Agent receives ConnectorResponse. | async |

End-to-end enforcement boundary latency (steps 1–4): **\< 3 ms p95**.

## **5.2   Canonicalisation**

The Interceptor transforms the raw agent call into an ExecutionEnvelope. This is a semantic transformation, not a format conversion. After canonicalisation, the original agent representation is discarded; the canonical envelope becomes the only trusted execution representation. No component downstream of the Interceptor has access to the original call.

## **5.3   Stage 1 — Token Verification**

Stage 1 validates the CapabilityToken carried in the envelope. Checks: cryptographic signature, token expiry, and presence in the local revocation list. Stage 1 does **not** invoke the Cedar engine. A Stage 1 failure produces an immediate DENY without proceeding to Stage 2\.

## **5.4   Stage 2 — Constraint Enforcement Engine (CEE)**

Stage 2 evaluates the envelope against the local policy bundle using the Cedar policy engine. Evaluation inputs: the envelope intent, the capability scope, the current budget, and any threshold conditions defined in the policy. The result is a binary ALLOW or DENY. No network calls are made during Stage 2\.

# **6\.   Provenance Protocol**

The Provenance Protocol defines how the causal chain of an action is captured and made available for post-hoc audit and replay. It answers: **why** did the agent make this call?

* **Protocol commitment:** The `provenance` field is present in the ExecutionEnvelope schema as a first-class field. Its position and type are stable across v0.1-compatible implementations.  
* **v0.1 status:** The field is a schema-reserved placeholder. The runtime does not populate it. Implementations must accept envelopes where provenance is empty.  
* **Intended future semantics:** causal chain linking this action to the prior agent reasoning step or instruction; structural basis for deterministic replay; attestation anchor for compliance-grade audit backends.  
* **Out of scope for v0.1:** provenance capture runtime, replay tooling, Firma Chain audit export.

# **7\.   Decision Semantics**

FEP defines four decision outcomes. Three are synchronous enforcement results; one is an asynchronous in-flight termination signal. They are not interchangeable.

| Decision | Layer | Call reaches target? | Returned as | Agent loop behavior |
| :---- | :---- | :---- | :---- | :---- |
| **ALLOW** | Tool / API | Yes | Normal result | Continue |
| **DENY** (tool) | LLM / tool loop | No | **Simulated tool output** | Continue — agent reasons about denial |
| **DENY** (API) | Network / API | No | Hard error to caller | Caller handles; no loop continuation expected |
| **ABORT** | In-flight | Interrupted | Abort signal to Sidecar | Terminate active execution |

## **7.1   Tool Denial**

When a DENY is issued against a tool call, the Sidecar must return a **structured tool result** — a machine-readable denial value that the agent loop can consume, log, and reason about. Raising an exception or terminating the session is non-conformant. The denial is still recorded in the audit stream.

## **7.2   API Denial**

When a DENY is issued against a direct API call (HTTP, DB, or non-tool connector), the Sidecar returns a hard authorization failure to the caller. The target system is never reached. The caller is responsible for handling the failure.

## **7.3   ABORT**

ABORT is not an enforcement decision. It is an **asynchronous in-flight kill signal** issued while execution is already in progress — typically triggered by a revocation event arriving on the `WatchRevocations` stream. The Sidecar terminates any execution associated with the revoked capability. ABORT must not be confused with DENY: it is not evaluated by the CEE and does not appear in the synchronous decision path.

# **8\.   Authority vs. Sidecar Semantics**

Both the Authority and the Sidecar perform Cedar-based policy evaluation. They evaluate different questions, at different times, with different inputs.

| Dimension | Authority | Sidecar |
| :---- | :---- | :---- |
| Question | **Can this capability exist?** | **Can this call happen right now?** |
| When | At issuance time — before execution begins | At action time — inline, per call |
| Inputs | Session identity, agent identity, requested scope | ExecutionEnvelope, local policy bundle, budget, revocation state |
| Output | Signed CapabilityToken (or rejection) | ALLOW or DENY |
| Hot path? | **No** | **Yes** |
| Network calls? | May call identity/policy systems at issuance | None — fully local |
| Can override other? | Defines ceiling; cannot be overridden by Sidecar | Enforces within ceiling; cannot extend it |

This two-phase structure ensures that policy enforcement at runtime is deterministic, local, and sub-millisecond, while issuance-time decisions can use richer context (identity systems, environment state) without affecting hot-path latency.

# **9\.   Connector Boundary Rules**

The Connector is a **protocol adapter** only. It receives an already-authorised, credential-injected ExecutionEnvelope and translates it to the target-system wire format. The following rules are normative.

## **9.1   Permitted operations**

* Translate the ExecutionEnvelope to the target-system wire format (HTTP request, SQL call, tool payload, etc.).  
* Apply technical constraints: connection pool management, retry policy, timeout enforcement, target-system rate limits.  
* Read and forward the credentials injected by the Credential Injector.  
* Return a `ConnectorResponse` to the Sidecar.

## **9.2   Prohibited operations**

* **Authorization decisions.** The Connector has no access to the capability token, Cedar engine, or policy bundle. It must not conditionally suppress or allow actions based on request content.  
* **Modifying envelope fields.** The envelope is immutable. The Connector must not alter intent, capability, or metadata fields after receiving the envelope.  
* **Business logic.** Routing conditions, scope transformations, approval gates, or any logic that depends on the semantic content of the request — rather than its technical delivery — is forbidden in Connector code.  
* **Independent credential sourcing.** Credentials must arrive via the Credential Injector after Stage 2 ALLOW. The Connector must not fetch, cache, or derive credentials from external systems.  
* **First-time semantic classification.** The Connector must not determine the canonical action class of the incoming action. By the time a request reaches the Connector, `intent.action_class` must already be set in the ExecutionEnvelope. Connectors may enrich transport-specific technical fields for protocol translation purposes, but must not act as the primary policy surface for an action.

**Note:** Violations of the Connector boundary do not produce immediate runtime errors. They produce silent, untraceable policy bypass. All Connector implementations must be reviewed against these rules at every change.

# **10\.   Identity and Trust Boundary**

**FEP is not an identity protocol**. It does not perform primary authentication, manage credentials for human principals, or issue identity tokens. These responsibilities belong to infrastructure or upstream identity systems (e.g., workload identity, service mesh, external IdP).

| Component | Identity responsibility |
| :---- | :---- |
| Infrastructure / IdP | Primary authentication of principals and workloads. FEP assumes this has been completed before issuance. |
| Authority | Consumes verified identity context as input to IssueCapability. Does not verify identity itself. Issues capability-scoped tokens, not identity tokens. |
| Sidecar | Enforces capability-bound actions. Operates on CapabilityTokens, not identity tokens. Does not authenticate the agent — it verifies that the capability authorises the action. |
| Connector | Injects execution credentials obtained via the Credential Injector. Does not authenticate to target systems independently. |

The boundary: FEP assumes the transport is authenticated by infrastructure or upstream identity systems. FEP does not provide or verify transport-level authentication. Implementations that expose FEP endpoints without upstream transport authentication are non-conformant.

# **11\.   Versioning and Compatibility**

## **11.1   v0.1 Status**

v0.1 is a **semantic draft**. The protocol semantics and invariants defined in this document are stable commitments. The protobuf wire format is **not yet frozen** — field numbers, message names, and service definitions may change before v1.0. Implementations built against v0.1 should treat the wire format as internal until the v1.0 freeze.

## **11.2   Reserved Fields**

The following capabilities are schema-reserved in v0.1. They appear as fields or placeholders in the protobuf contracts but are not implemented in the runtime:

* `provenance` field on ExecutionEnvelope — causal chain and replay.  
* Escalation engine and WatchAborts stream — reserved for post-v1 synchronous escalation outcomes. A future ESCALATE decision type is anticipated; it will not break invariant \[I-D1\] (binary synchronous decisions) because escalation is definitionally a third outcome that suspends, not completes, the execution path.  
* Trust graph and dynamic risk engine — for risk-weighted capability issuance.  
* Full Firma Chain audit backend — compliance-grade event export.  
* Multi-tenant control plane — per-tenant policy isolation.

## **11.3   Compatibility Goal**

Future versions of FEP will be backward-compatible with the invariants defined in §3. An implementation conformant with v0.1 invariants will remain conformant under future versions, provided it does not depend on wire format details that are not yet frozen. Unknown or reserved fields must be ignored unless the field is explicitly marked security-critical (such as capability or enforcement decision fields). Implementations must not silently accept unknown values in security-critical positions.

The semantic specification precedes the wire freeze. Protocol behaviour is stable; wire serialisation details are not.

# **12\.   Relationship to Protobuf Contracts**

| Artifact | Role | Source of truth for |
| :---- | :---- | :---- |
| This specification | Semantic source of truth | Protocol invariants, decision semantics, component boundary rules, versioning policy |
| `firma/v1/types.proto` | Wire format contract | Message field definitions, types, field numbers, enums for ExecutionEnvelope, CapabilityToken, EnforcementDecision, etc. |
| `firma/v1/authority.proto` | RPC contract | AuthorityService method signatures: IssueCapability, WatchPolicyBundle, WatchRevocations |
| Implementation code | Runtime realisation | Must satisfy both this specification and the protobuf contracts. Schema validity is necessary but not sufficient for conformance. |

A protobuf message that passes schema validation but violates a protocol invariant (§3) is **non-conformant**. Schema validity is a floor, not a ceiling. For example: a Connector implementation that performs Cedar evaluation before dispatching is schema-valid but violates invariant \[I-C1\] and is therefore non-conformant with this specification. Future OSS conformance suites should validate invariant compliance, not only schema compatibility. Conformance testing should cover: Connector boundary rules (§9), decision semantics (§7), and the Authority off-path guarantee (§4.3).

# **13\.   Conformance Levels**

A FEP v0.1 implementation is conformant at one or more of the following levels. Each level is additive — conformance at a higher level implies conformance at all lower levels. Implementations must declare their conformance level explicitly.

## **13.1   Core-conformant**

A Core-conformant implementation satisfies the following:

* **Protocol invariants.** All invariants defined in §3 are enforced.  
* **Envelope immutability.** The ExecutionEnvelope is immutable from the point the Interceptor creates it through Connector dispatch.  
* **Connector boundary.** The Connector boundary rules of §9 are enforced. The Connector does not make authorization decisions, modify intent, or perform semantic classification.  
* **Stage 1 and Stage 2 local evaluation.** Token verification (§5.3) and Cedar policy evaluation (§5.4) execute inside the Sidecar before any Connector dispatch.

## **13.2   Registry-conformant**

A Registry-conformant implementation is Core-conformant and additionally satisfies:

* **Canonical Action Class Registry support.** The implementation recognizes and enforces all action classes defined in the v0.1 registry (§2.3.5).  
* **Intent Normalization.** The Intent Normalizer maps raw runtime events to registry-defined action classes before Stage 1 and Stage 2 evaluation, as specified in §2.2.  
* **Fail-closed on unclassifiable protected actions.** The Sidecar returns DENY: UNCLASSIFIED\_INTENT when a protected action cannot be deterministically classified. No Connector dispatch occurs.  
* **Policy binding to action\_class.** Stage 2 policy rules bind to intent.action\_class and intent.resource, not to transport-specific fields.

## **13.3   Audit-conformant**

An Audit-conformant implementation is Registry-conformant and additionally satisfies:

* **Normalized action class in audit events.** Every audit event records the value of intent.action\_class at the time of the enforcement decision.  
* **Deterministic decision trace.** Each audit event includes sufficient provenance fields to reconstruct the enforcement decision deterministically (see §15 for minimum required fields).  
* **Decision and denial reason.** Audit events record the decision outcome and, for DENY decisions, the deny reason.

## **13.4   HITL-conformant**

A HITL-conformant implementation is Audit-conformant and additionally satisfies:

* **HITL conditions bound to intent.action\_class.** Human-in-the-loop trigger conditions reference intent.action\_class from the registry, not transport-specific names.  
* **Approval payload binding.** The approval request presented to the human operator includes the normalized action class and resource from the ExecutionEnvelope.  
* **No free-form chat approval.** HITL approval is not satisfied by unstructured conversational confirmation. Approval must reference the specific envelope under review.  
* **Approval binding.** Approval MUST include a stable hash of the complete normalized action payload — covering `intent.action_class`, `intent.resource`, and `intent.parameters` — and an explicit expiry timestamp. This prevents replay attacks, delayed approval misuse, and modified-body same-envelope confusion. An approval whose hash does not match the envelope under execution must be rejected.  
* **HITL decision recorded in audit trail.** The human operator decision, timestamp, and operator identity are included in the audit event for the relevant enforcement decision.

# **14\.   Security Considerations**

This section enumerates the primary security threats against FEP-conformant deployments. Implementors should evaluate their deployment against each threat class. The threats are ordered from highest to lowest likelihood of exploitation in v0.1 deployments.

**Semantic bypass via transport leakage.** An agent or connector routes a high-risk action through a transport-specific name (e.g. exec, http.post) that does not map to a registry-defined action class, causing policy and HITL conditions to not fire. Mitigated by mandatory Intent Normalization (§2.2) and fail-closed behaviour on DENY: UNCLASSIFIED\_INTENT. This is the primary threat class that motivated the registry-based normalization model in FEP v0.1.

**Connector policy smuggling.** A Connector implementation applies additional policy gates, conditionally suppresses actions, or performs semantic classification after receiving an authorised envelope, creating an unauthorized second enforcement layer outside the Sidecar. Mitigated by §9 Connector Boundary Rules and conformance level enforcement.

**Registry drift across runtimes.** Two FEP deployments use different action class identifiers for the same semantic action, causing policy rules authored for one deployment to silently fail to fire in another. Mitigated by the versioned Canonical Action Class Registry (§2.3) and the naming rules of §2.3.2.

**Low-risk pass-through abuse.** An implementation classifies a high-risk action as a low-risk transport-preserving operation to exempt it from Intent Normalization enforcement, exploiting the permit-list exception in §2.3.3. Mitigated by requiring the permit-list to be explicit, statically configured, and reviewed at deployment time.

**Capability replay risk.** A valid CapabilityToken is captured and replayed to authorize a different action or in a different session context than originally intended. Mitigated by envelope binding, session scope constraints, and the Authority off-path guarantee (§4.3).

**Raw shell fallback overuse.** Implementations route all execution actions through system.execute to avoid the cost of specific classification, reducing the policy signal-to-noise ratio and making HITL triggers ineffective. Mitigated by the anti-convenience-class rule for system.execute (§2.3.6) and Registry-conformant audit requirements.

**Privilege boundary assumptions.** A Connector or downstream system assumes that an authorised envelope implies broader permissions than the specific action class and resource encoded in the envelope. Mitigated by the principle that capability scope is bounded to the specific action\_class and resource at issuance time.

**HITL channel spoofing.** An attacker injects a forged HITL approval response into the approval channel, causing the Sidecar to treat an unauthorized action as human-approved. Mitigated by HITL-conformant implementations binding approval to the specific envelope under review and recording operator identity in the audit trail.

**Probabilistic normalization drift.** Use of non-deterministic classifiers or language models in the Intent Normalizer may cause identical protected actions to normalize to different registry classes across repeated executions, silently weakening policy guarantees and breaking audit reproducibility. FEP v0.1 prohibits probabilistic normalization on the hot path. Intent Normalization must be implemented as a deterministic canonicalization step with no language-model, SLM, or similarity-based classification component.

**Policy proposal privilege escalation.** An agent drafts a policy proposal that, if auto-published or published without external approval, expands its own permission perimeter. The policy bundle promotion path must be authenticated and out-of-band from the agent's execution context — the proposing agent must not be able to influence the promotion decision. Mitigated by separating proposal creation from trusted policy publication and enforcing external HITL approval on bundle promotion through a trusted operator path. Bundle version changes must be recorded in the audit trail.

# **15\.   Audit Minimum Fields**

Audit-conformant implementations (§13.3) must record the following fields in every audit event. All fields are normative (MUST). Implementations may record additional fields; they must not omit any field in this list.

* `timestamp` — ISO 8601 timestamp of the enforcement decision.  
* `session_id` — Stable identifier for the agent session in which the action was attempted.  
* `agent_id` — Identifier of the agent that generated the action.  
* `action_class` — The normalized canonical action class from intent.action\_class at the time of enforcement. Must be a registry-defined identifier.  
* `resource` — The normalized target resource from intent.resource.  
* `decision` — The enforcement outcome: ALLOW, DENY, DENY:UNCLASSIFIED\_INTENT, DENY:AMBIGUOUS\_INTENT, or ABORT.  
* `deny_reason` — For DENY decisions: the specific reason code. Omitted for ALLOW.  
* `bundle_version` — Version identifier of the policy bundle active at the time of the decision. Required for deterministic replay.  
* `registry_version` — Version identifier of the Canonical Action Class Registry active at the time of normalization. Required for deterministic replay across registry upgrades.  
* `trace_id` — Correlation identifier linking the audit event to the originating agent request and any downstream system calls.  
* `approval_id` — Stable identifier for the HITL approval event associated with this enforcement decision. REQUIRED for HITL-conformant decisions; omitted for non-HITL decisions. Must be generated at approval request time, not at decision time, to prevent retroactive construction. Must be recorded in both the approval payload and the audit event for cross-reference.

The fields `bundle_version` and `registry_version` together constitute the minimum provenance required to deterministically reproduce an enforcement decision in a replay or conformance audit context.

# **16\.   Normative Examples**

The following examples illustrate the three canonical execution paths through the FEP enforcement pipeline. They are normative: conformant implementations must produce the outcomes described.

## **16.1   Example A — Semantic canonicalization (ALLOW path)**

An agent invokes a Telegram send action via an `exec` tool call. The raw transport identifier is `exec`, which carries no semantic meaning. The Intent Normalizer inspects the action payload and deterministically maps it to the registry-defined class for external communication:

* Raw event: `exec telegram_send --chat-id 123 --text "..."`  
* Normalized: `intent.action_class = communication.external.send`  
* Normalized: `intent.resource = telegram://chat/123`

Stage 2 policy evaluation fires against `communication.external.send`. If a HITL condition is bound to this class, the operator approval request is raised. The raw `exec` transport identifier is preserved in `intent.raw_transport` for audit only and is not used for policy evaluation.

## **16.2   Example B — Registry fallback (system.execute path)**

An agent invokes a shell command whose business purpose cannot be deterministically elevated to a narrower semantic class. The Intent Normalizer falls back to the bounded high-risk fallback class:

* Raw event: arbitrary shell invocation with ambiguous business purpose  
* Normalized: `intent.action_class = system.execute`

Because `system.execute` is a high-risk class, it must trigger HITL review unless explicitly permitted by policy. The use of `system.execute` as a fallback does not reduce the policy signal — it ensures the action is subject to enforcement rather than bypassing it. Implementations must not route actions to `system.execute` when a more specific registry class applies.

## **16.3   Example C — Fail-closed path (DENY: UNCLASSIFIED\_INTENT)**

An agent invokes a novel vendor-specific API action that does not correspond to any class in the v0.1 registry and cannot be mapped to `system.execute` or any other registry entry:

* Raw event: vendor-specific API call with no registry mapping  
* Intent Normalizer: unable to determine canonical action class  
* Outcome: `DENY: UNCLASSIFIED_INTENT` — no Connector dispatch, token state unchanged

This is the correct fail-closed outcome. The Sidecar does not attempt to infer a classification from context. The deny reason is recorded in the audit event. The implementation must not fall back to a permissive default for unclassifiable actions.

## **16.4   Example D — HITL envelope binding (replay → DENY)**

An operator approves a Telegram send action. A subsequent replay attempt submits the same approval token against a modified message body. The approval binding check detects the payload hash mismatch and denies the replayed action.

Initial approved action:

* `intent.action_class` \= `communication.external.send`  
* `intent.resource` \= `telegram://chat/123`  
* `intent.parameters` \= `{ "text": "Deployment approved." }`  
* `payload_hash` \= SHA-256(`action_class || resource || parameters`) \= `e3b0c44…`  
* `approval_id` \= `appr_7f3a9c` (issued at T, expires T+300s)

Replay attempt (modified body, same approval token):

* `intent.parameters` \= `{ "text": "Funds transferred." }`  
* `payload_hash` \= SHA-256(recomputed) \= `9f86d08…` ≠ `e3b0c44…`  
* Outcome: `DENY` — payload hash mismatch. Approval `appr_7f3a9c` is not valid for this envelope.

The replay is denied before reaching Stage 2 policy evaluation. The approval token is single-use and bound to the exact normalized payload hash at approval time. Modifying any of `action_class`, `resource`, or `parameters` after approval invalidates the binding. The deny event is recorded in the audit trail with `deny_reason = APPROVAL_BINDING_MISMATCH` and the original `approval_id`.