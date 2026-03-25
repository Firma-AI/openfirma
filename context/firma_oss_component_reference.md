# **Firma AI — Open Source Release**

`Component Reference  ·  v1`

| This document describes every component included in the Firma AI open-source release (Apache 2.0). It is the primary reference for the team building on top of the OSS package. It explicitly calls out V1 scope boundaries, failure modes, and what is intentionally excluded. |
| :---- |

## **0\. Terminology**

Core terms used throughout this document. Definitions are grouped by layer. Refer to this section before reading any component description.

| Entities |  |
| :---- | :---- |
| **Agent** | The full orchestration layer: LLM model \+ tool executor \+ session state. Firma treats the agent as the principal requesting capabilities. Not synonymous with “LLM” — the LLM is one component inside the agent. |
| **Authority** | The control-plane component that evaluates policies at issuance time and issues capability tokens. Defines the permission perimeter before execution begins (scope, budget, expiry) and distributes policy bundles and revocations to Sidecars. Contacted only at session start (pre-flight), never on the hot path. |
| **Sidecar** | The local enforcement process deployed alongside each agent. Runs Stage 1 (capability validation) and Stage 2 (Cedar policy eval). Fail-closed: denies all requests if the policy bundle TTL expires without a successful refresh. |
| **Core Concepts** |  |
| **Capability** | A scoped, time-bounded permission granted to an agent for a specific action class (e.g. “write to Postgres table orders, max 50 rows, expires in 10 min”). Issued by Firma Authority before execution begins. Defines the permission perimeter. The Sidecar enforces constraints within it but cannot extend or override it. |
| **Capability Token** | The signed, serialized form of a capability. Encoded as PASETO v4 (preferred) or JWT RS256. Carries capability claims, agent identity, expiry, and a unique Token ID used for revocation. |
| **Permission Perimeter** | The boundary of allowed actions, resources, budget, and expiry defined by a capability. Enforced by the Sidecar but cannot be extended or overridden at runtime. |
| **Execution Envelope** | The core protocol unit of the Firma system. The protocol object wrapping each outbound call: intent, capability token reference, call metadata, and provenance. Each outbound call is represented as a distinct Execution Envelope evaluated independently by the Sidecar. Every request is evaluated, enforced, and audited as an Execution Envelope. Treated as immutable once created — any enrichment should produce a derived structure. |
| **Execution Context** | The set of attributes used during Cedar evaluation (e.g. agent identity, resource, budget remaining, risk score). Built from the Execution Envelope, Sidecar local state, and pre-computed attributes. Some attributes may originate from the agent and should be treated as untrusted unless verified or recomputed by the Sidecar. |
| **Enforcement** |  |
| **Stage 1 — Capability Validation** | First enforcement phase: token parse, signature verify, expiry check, revocation check via bloom filter. Fully local, \< 1ms p95. |
| **Stage 2 — Constraint / Policy Enforcement (CEE)** | Second enforcement phase: context build, Cedar eval, scope / budget / threshold checks. Fully local, \< 200µs p95. |
| **Constraint Enforcement Engine (CEE)** | The Stage 2 component of the Sidecar responsible for evaluating Cedar policies and applying runtime constraints (budget, scope, thresholds). |
| **Cedar Evaluation** | Deterministic policy evaluation executed locally in the Sidecar (Stage 2\) or Authority (issuance). Takes a request context and policy bundle as input and returns ALLOW / DENY. Evaluation is fully local — no external calls are made or allowed. |
| **Runtime Mechanics** |  |
| **Hot Path** | Any outbound call originating from the agent: tool execution, external API calls, database queries, LLM API calls. Every such call passes through the Sidecar (Stage 1 \+ Stage 2\) before reaching the target. No round-trip to Firma Authority on the hot path — all evaluation is local. |
| **Session** | The logical execution window of an agent. A session may involve multiple calls and one or more active capabilities, each scoped independently. Bound by the expiry and scope of its active capability tokens. |
| **Revocation** | The invalidation of a previously issued capability token. Propagated from the Authority to the Sidecar via streaming and enforced locally in Stage 1 with no network calls at decision time. |
| **Fail-Closed** | A system behavior where requests are denied if required policy or control-plane data is unavailable (e.g. expired policy bundle). |
| **Abort** | Immediate termination of an in-flight request triggered by the Authority or Sidecar. |
| **Integration** |  |
| **Connector** | The adapter layer translating the Execution Envelope into the target system protocol. Applies technical constraints only (e.g. rate limits, schema validation), not business or policy logic. Connectors must never implement policy decisions — violating this breaks auditability and system guarantees. |
| **Policy Bundle** | The set of Cedar policy files (.cedar \+ entity schema) loaded by the Sidecar at startup and kept current via WatchPolicyBundle. Stored as human-readable text; compiled into an in-memory policy set at load time. Treated as immutable during evaluation — Stage 2 evaluates against a stable snapshot. No parsing on the hot path. If a new bundle fails to parse, the Sidecar retains the last valid set. Default TTL: 30s. |
| **Policy Bundle Version** | The version identifier of the currently active policy bundle used during Cedar evaluation. Used for debugging and audit correlation. |
| **WatchPolicyBundle** | The Sidecar component that maintains policy freshness. Pulls or receives policy bundle updates from the Authority on a configurable TTL (default 30s). If a refresh fails and the TTL expires, the Sidecar transitions to fail-closed. |
| **Mini Authority** | A lightweight, file-based Authority implementation for local development and testing. Loads Cedar policies from disk and issues capability tokens without a network dependency. Not intended for production use. |
| **Audit Event** | A signed record emitted by the Sidecar for each decision (ALLOW / DENY / ABORT), including context, decision, and metadata. Used for traceability and compliance. |
| **Token ID** | Unique identifier embedded in a capability token, used for tracking and revocation lookups. |

## **1\. Security Boundary — Containment vs Policy Enforcement**

Before describing any component, this distinction must be stated clearly:

| Firma Sidecar (this OSS package) | Sandbox / host runtime |
| :---- | :---- |
| L7 / application-layer policy enforcement | Process / OS-level containment |
| Decides what agent calls are allowed, denied, or aborted | Decides what code the agent process can execute |
| Enforces Cedar policies, capability scope, budget limits | Enforces filesystem, network, syscall restrictions |
| Acts after the agent has decided to make a call | Acts on the agent runtime itself |
| Can be replaced by config change (Mini Auth → FA) | Orthogonal to Firma; managed by the deployment platform |

| The Sidecar is NOT the hard security boundary for process isolation. It enforces what an agent is authorised to do at the API/call level. The sandbox (container isolation, seccomp, etc.) is the boundary for runtime containment. Both are required; they do not substitute for each other. |
| :---- |

Anyone reading this OSS package should not conclude that deploying the Sidecar alone provides a complete security model. It provides the policy enforcement layer. The containment layer is out of scope for this release.

## **1.1  Component Security Model**

Each component in the Firma stack prevents a specific class of threats. This section maps components to threats to make the security model explicit and auditable.

| Component | Prevents |
| :---- | :---- |
| **Authority** | Prevents invalid or over-broad capabilities from being issued. Source of truth for policy and revocation state. |
| **Stage 1** | Prevents forged, tampered, expired, or revoked capabilities from entering the execution path. |
| **Stage 2 (CEE)** | Prevents valid capabilities from being misused for out-of-policy, over-budget, or contextually disallowed actions. |
| **Connector** | Prevents protocol-level misuse, malformed target requests, and integration-specific constraint violations at the system boundary. |
| **Credential Injector** | Prevents direct credential exposure and secret handling by the agent. |
| **Audit Emitter** | Prevents loss of traceability for enforcement decisions. |
| **Sandbox / runtime** | Prevents unsafe code execution and runtime escape outside the application-layer policy boundary. Orthogonal to Firma; managed by the deployment platform. |

### **Authority**

| Threat / Risk | What it prevents |
| :---- | :---- |
| **`over-broad capability issuance`** | Ensures capabilities are scoped to the minimum required actions, resources, and expiry. |
| **`unauthorized capability creation`** | Only authenticated agents with valid identity can request capabilities. |
| **`issuance outside policy perimeter`** | Cedar evaluation at issuance rejects requests that exceed defined policy boundaries. |
| **`inconsistent policy distribution`** | WatchPolicyBundle ensures all Sidecars operate on the same bundle version. |
| **`stale revocation propagation`** | WatchRevocations pushes invalidations to Sidecars immediately. |
| **`human-review bypass`** | Future: ESCALATE outcome enables human-in-the-loop for out-of-policy requests. V1 placeholder. |

| The Authority prevents invalid or over-broad capabilities from being issued in the first place and serves as the source of truth for policy and revocation state. |
| :---- |

### **Stage 1 — Capability Validation**

| Threat / Risk | What it prevents |
| :---- | :---- |
| **`token forgery`** | Cryptographic signature verification rejects tokens not signed by a trusted Authority. |
| **`token tampering`** | Any modification to scope, budget, expiry, agent ID, or resource scope invalidates the signature. |
| **`expired credential reuse`** | Expiry check rejects tokens whose TTL has elapsed regardless of other fields. |
| **`revoked token reuse`** | Bloom filter \+ LRU cache check rejects tokens that have been explicitly invalidated. |
| **`scope bypass at token layer`** | Signature covers the full scope claim; mismatched scope is detected at parse time. |
| **`replay of invalidated decisions`** | Revocation cache ensures previously valid but now-revoked tokens are rejected on every call. |
| **`unverified caller state`** | Only cryptographically verified claims are trusted. Agent-supplied fields are not trusted until verified. |
| **`hot-path dependency attacks`** | All Stage 1 checks are fully local. No remote call can be manipulated or made unavailable to affect the decision. |

| Stage 1 prevents forged, tampered, expired, or revoked capabilities from entering the execution path. |
| :---- |

### **Stage 2 — Constraint / Policy Enforcement (CEE)**

| Threat / Risk | What it prevents |
| :---- | :---- |
| **`privilege escalation within token`** | Cedar eval checks the specific call against policy, not just token validity. A valid token does not imply all calls are allowed. |
| **`out-of-policy actions`** | Endpoint, tool, operation, method, or resource not permitted by Cedar policy is denied. |
| **`budget overrun / quota abuse`** | Pre-computed budget\_remaining attribute checked against threshold before the call proceeds. |
| **`scope misuse at runtime`** | A valid capability for action class X cannot be used for action class Y. Cedar eval enforces this per call. |
| **`context-sensitive violations`** | Requests valid in isolation but not in the current context (time, session state, action count) are denied. |
| **`cross-namespace / cross-tenant access`** | Cedar namespace policies prevent agents from accessing memory, data, or resources outside their assigned namespace. |
| **`unsafe high-risk actions`** | Risk threshold policy denies calls whose static risk attribute exceeds the configured threshold. |
| **`policy drift into application code`** | Centralising decisions in Cedar prevents policy logic from leaking into agent code or connectors. |
| **`non-deterministic authorization`** | Same context \+ same bundle always produces the same decision. No external calls on the eval path. |

| Stage 2 prevents valid capabilities from being misused for out-of-policy, over-budget, or contextually disallowed actions. |
| :---- |

### **Connector / Adapter Layer**

| Threat / Risk | What it prevents |
| :---- | :---- |
| **`protocol misuse`** | Requests permitted by policy but malformed for the target are caught before dispatch. |
| **`malformed request emission`** | Payload validation ensures only well-formed requests reach the external system. |
| **`schema violations`** | Response schema validation prevents non-compliant outputs from being accepted. |
| **`target-specific unsafe combinations`** | Parameter combinations that are technically dangerous for a specific target are blocked. |
| **`rate-limit abuse at boundary`** | Per-target rate limits (e.g. 60 req/min to OpenAI) are enforced at the connector level. |
| **`format normalisation errors`** | Execution Envelope fields are translated correctly to the native target protocol. |
| **`credential leakage via agent`** | Credential injection by the connector means the agent never handles secrets directly. |
| **`audit blind spots at boundary`** | Call outcome, status, latency, and response size are normalised and passed to the audit emitter. |
| **`policy leakage into connectors`** | Technical constraints are kept local to the connector. Business policy stays in Cedar. |

| The Connector prevents protocol-level misuse, malformed target requests, and integration-specific constraint violations at the system boundary. It must never become a second policy engine. |
| :---- |

### **Audit Emitter**

| Threat / Risk | What it prevents |
| :---- | :---- |
| **`non-repudiation gaps`** | Every enforcement decision is signed and recorded. No decision goes unlogged. |
| **`loss of traceability`** | Structured events include context hash, bundle version, agent ID, and token ID for full reconstruction. |
| **`silent decision paths`** | ALLOW, DENY, and ABORT outcomes are all emitted. No outcome is silently dropped. |
| **`incomplete incident reconstruction`** | Event chain includes session ID and trace ID for cross-call correlation. |
| **`audit loss on sink disconnect`** | WAL buffer ensures events are persisted locally and replayed when the sink reconnects. |

| The Audit Emitter prevents loss of traceability for enforcement decisions. No call enters or exits the Sidecar without a signed audit record. |
| :---- |

### **Credential Injector**

| Threat / Risk | What it prevents |
| :---- | :---- |
| **`credential exposure to agent`** | Secrets are fetched by the Sidecar and injected transparently. The agent never sees them. |
| **`hardcoded secret sprawl`** | Vault-based injection means credentials are not embedded in agent code or config. |
| **`unsafe secret propagation`** | Credentials are injected per-call and are short-lived (Vault) or config-isolated (basic mode). |
| **`direct agent credential handling`** | Agent code has no path to receive or store credentials. |
| **`credential misuse outside target`** | Injection is scoped to the specific connector and target. Credentials do not leak cross-connector. |

| The Credential Injector prevents direct credential exposure and secret handling by the agent. The agent operates without ever holding secrets. |
| :---- |

## **2\. Execution Pattern**

Every agent call flows through five stages inside the Sidecar, in sequence. The Authority is not on the hot path. It is contacted only during capability issuance (pre-flight), either at session start or when new capabilities are required. It is never contacted during call execution.

A session does not imply a single capability. Multiple capabilities can coexist and be used independently across calls within the same session.

| `Stage 1 — Capability Validation` | First enforcement phase. Validates the capability token: parse, signature verify, revocation check. Fully in-process, no network call. Runs in under 1 ms. |
| :---- | :---- |
| **`Authority (pre-flight only)`** | Called during capability issuance (pre-flight) to issue signed capability tokens. This may occur at session start or during an active session when new capabilities are required. Streams policy bundle and revocation updates in background. Not contacted again on the hot path. |
| **`Stage 2 — Constraint / Policy Enforcement`** | Second enforcement phase (CEE). Builds Cedar context, evaluates Cedar policies, applies budget / scope / threshold checks. Fully local. |
| **`Connector`** | Translates the Execution Envelope to the target protocol. Applies target-specific technical constraints. Normalises the audit event. |
| **`External`** | The downstream system: LLM API, database, third-party service, etc. |

| Stage 1 and Stage 2 are two sequential enforcement phases inside the same Sidecar process, not two separate components. Every outbound call passes through both phases in a single binary. The Authority is never contacted on this path. |
| :---- |

## **3\. Mini Authority**

Mini Authority is the reference implementation of the Firma Authority interface. Its sole purpose is to make the full OSS stack runnable locally without any cloud service. It is intentionally minimal: no risk engine, no trust graph, no multi-tenancy.

### **3.1  Cedar policy loader**

Reads every .cedar file from /policies at process startup. No hot-reload on the loader itself. Policy updates reach the Sidecar via the WatchPolicyBundle stream. File changes require a process restart to take effect in the loader, but the stream will push the new bundle to connected Sidecars automatically.

### **3.2  IssueCapability RPC**

The core gRPC endpoint consumed by the Sidecar during capability issuance (pre-flight). It may be called at session start or during an active session to obtain additional or refreshed capability tokens. Receives agent identity, requested actions, resource scope, and session metadata. Evaluates the request against loaded Cedar policies. On success, returns a signed capability token (PASETO v4 or JWT RS256). On denial, returns a reason code.

### **3.3  WatchPolicyBundle RPC**

Persistent server-streaming gRPC call. Immediately streams the current policy bundle on connect, then pushes incremental updates. In Mini Authority this is driven by filesystem watch on /policies. If this stream disconnects and the Sidecar’s cached bundle TTL expires (default 30 s), the Sidecar enters fail-closed mode and denies all new requests.

### **3.4  WatchRevocations**

Persistent server-streaming gRPC call that pushes revocation events. In Mini Authority this is mock / file-based: write to revocations.json, Mini Authority streams the update. The Sidecar Stage 1 maintains a bloom filter and LRU cache from this stream, enabling sub-microsecond revocation checks with no network I/O.

### **3.5  Capability token generation**

Generates capability tokens using the Capability Library (see section 5). Two formats: PASETO v4 (default) and JWT RS256. Token payload: session ID, agent ID, action set, resource scope, issued-at, expiry, and an integrity hash of the Cedar context used at issuance.

| Mini Authority is labeled "reference impl · dev / test / demo · not for production". Never deploy it as a real authority endpoint. In production, swap it for Firma Authority via a single config-file change: firma.authority: FA\_URL. The Sidecar binary does not change. |
| :---- |

## **4\. Firma Sidecar**

Firma Sidecar is the primary OSS component. It is the enforcement layer between an agent and the outside world. Every outbound call passes through it. The Sidecar is a single statically-linked binary with no persistent database; all state is in-memory and re-populated from Authority streams on restart.

### **4.1  Interceptor**

Captures outbound agent traffic before it reaches the external system. Three modes today:

* HTTP proxy (port 8080 default) — agent sets HTTP\_PROXY=http://localhost:8080.

* gRPC hook — programmatic interceptor registered within the agent process.

* Unix socket — local socket, avoids port binding in containers.

* eBPF (roadmap) — kernel-level capture, no agent-side config required.

Regardless of interception mode, the output is always a structured Execution Envelope passed to Stage 1\. If the intercepted request cannot be parsed into a valid Execution Envelope, the Sidecar returns a structured DENY with reason MALFORMED\_REQUEST. The agent must handle this as a recoverable error, not a fatal failure.

### **4.2  Execution Envelope**

The core protocol unit of the Firma system. Each outbound call is represented as a distinct Execution Envelope, evaluated independently by the Sidecar. Every request is evaluated, enforced, and audited as an Execution Envelope. Treated as immutable once created — any enrichment (e.g. credential injection) produces a derived structure, not a mutation.

| `intent` | Action type, target resource identifier, action-specific parameters. |
| :---- | :---- |
| **`capability`** | Signed capability token issued by the Authority at pre-flight. Used by Stage 1 to verify identity and scope. |
| **`metadata`** | Session ID, agent ID, timestamp, trace ID, runtime signals (budget consumed, etc.). |
| **`provenance`** | Optional / forward-compatible field (V1: schema placeholder). Intended as a hash chain anchoring this envelope to the session’s prior calls. Not implemented in V1 runtime. Teams should treat this field as reserved and not build hard dependencies on it yet. |

| V1 note on provenance: the field is present in the schema to keep the protocol forward-compatible, but the runtime does not populate or verify the hash chain in V1. It is a placeholder. If your connector or audit logic reads this field, treat it as optional and nullable. |
| :---- |

### **4.3  Stage 1 — Capability Validation**

First enforcement phase. Runs synchronously in the request path. Target latency: under 1 ms. Steps:

* Token parse — deserialise the capability token from the Execution Envelope.

* Signature verification — verify cryptographic signature against the Authority public key. Rejects tampered or forged tokens immediately.

* Revocation check — query the revocation bloom filter (O(1) negative check) \+ LRU cache for confirmed positives. No network I/O.

If Stage 1 passes, the envelope proceeds to Stage 2\. If it fails, the call is denied with a structured DENY response. The Authority is never contacted.

### **4.4  Stage 2 — Constraint / Policy Enforcement (CEE)**

Second enforcement phase. The semantic layer where Cedar policies and quantitative constraints are evaluated. Steps:

* Context build — assembles the Cedar request context from envelope fields, local state, and runtime signals.

* Cedar eval — evaluates against the current policy bundle. Deterministic: same context \+ same bundle \= same decision. Evaluation is fully local — no external calls are made or allowed. Runs in microseconds.

* Budget / scope / threshold checks — applies quantitative constraints via pre-computed Cedar context attributes. In V1 these are static or pre-computed values injected before eval: remaining budget, allowed scope, a risk threshold from the Execution Envelope metadata. There is no dynamic risk engine in the OSS release.

| V1 note on risk: Stage 2 applies threshold-based checks on a static or pre-computed risk attribute. It does not compute risk dynamically. "Risk score" in the OSS context means: a numeric value injected by the agent runtime (or defaulting to 0\) checked against a configured threshold in Cedar. A full dynamic risk engine is a proprietary Firma Authority capability, not part of V1 OSS. |
| :---- |

Possible outcomes: ALLOW (envelope forwarded to Connector), DENY (call blocked, structured response returned), ABORT (mid-flight kill sent to agent and Connector).

### **4.5  Local State**

| `Policy bundle cache` | Current serialised Cedar bundle from WatchPolicyBundle. CEE reads this on every call. Includes version number and TTL. If TTL expires without refresh, Sidecar enters fail-closed mode. |
| :---- | :---- |
| **`Revocation cache`** | Two-layer: bloom filter for O(1) negative checks, LRU cache for confirmed revocations. Populated from WatchRevocations stream. No network I/O at check time. |

Neither cache is persisted to disk. On restart, the Sidecar re-fetches both from Authority streams before accepting traffic.

### **4.6  Audit Emitter**

Serialises every enforcement decision into a signed ExecutionEvent and forwards to one or more sinks. Each event contains: event ID (UUID v7), session ID, token ID, agent ID, action, resource, decision (ALLOW / DENY / ABORT), deny reason, enforcement latency (µs), context hash, bundle version, timestamp (ns), ECDSA signature over all preceding fields.

Four output modes: file (append-only), stdout (default for containers, structured JSON lines), gRPC (streaming to downstream audit service), and WAL on disconnect (events buffered on disk if gRPC stream drops, replayed on reconnect — no audit events are lost).

### **4.7  Credential Injector**

Runs after Stage 2 ALLOW, before the envelope reaches the Connector. Fetches credentials for the target system and injects them transparently. The agent never handles credentials directly. Two modes: Vault client (short-lived secrets from HashiCorp Vault or compatible), and basic credential injection (pre-configured API key / bearer token from Sidecar config).

## **5\. Capability Library**

Shared cryptographic utility library used by both the Sidecar and Mini Authority. Pure crypto logic, no network dependency, no side effects. Available in Go, Python, and TypeScript.

| `Token validation` | End-to-end validation: deserialise, check format, verify signature, check expiry, check scope against requested action/resource. Returns structured result with reason code on failure. |
| :---- | :---- |
| **`Parse + verify + sign`** | Low-level primitives: parse token to struct, verify signature with public key, sign payload with private key. |
| **`PASETO v4 / JWT RS256`** | Two formats: PASETO v4 (default, Ed25519 or XChaCha20-Poly1305) and JWT RS256 for environments with existing JWT infrastructure. Same logical payload schema. |
| **`Expiry + scope checks`** | Helpers to check validity window and whether token scope covers a specific requested operation. |
| **`Helper SDK`** | Language wrappers for Go, Python, TypeScript. Idiomatic ergonomics over shared primitives. Used by Sidecar (Go) and Mini Authority (Go). Available to agent developers for offline token inspection. |

## **6\. Example Agents**

Runnable reference applications demonstrating the full Firma execution flow end-to-end. Not production-grade agents; designed to be readable and copy-paste friendly. Both connect to the Sidecar via HTTP proxy (HTTP\_PROXY=http://localhost:8080) with no code-level integration required.

### **6.1  Python agent**

Targets OpenAI, Anthropic, and generic HTTP APIs. Exercises three scenarios:

| `ALLOW` | Call satisfies all Cedar policies and CEE constraints. Sidecar forwards it, agent receives a normal response. |
| :---- | :---- |
| **`DENY`** | Call violates a constraint (disallowed endpoint, budget exceeded, etc.). Sidecar blocks it with a structured denial. |
| **`ABORTED`** | Call killed mid-flight by an abort signal from the Authority. Agent receives a connection abort. |

### **6.2  TypeScript / Node agent**

Same three scenarios using axios and native fetch. Compatible with LangChain.js and Vercel AI SDK. Structurally identical to the Python agent, confirming Firma is language-agnostic at the agent layer. Both agents log the enforcement decision and latency for each call.

## **7\. Connector · Adapter Layer**

Sits between Stage 2 (CEE) and the external system. Responsible for protocol translation, target-specific technical constraints, and audit normalisation.

| `Translate Execution Envelope → target protocol` | Converts the Firma-internal Execution Envelope to the target system’s native protocol (HTTP, gRPC, DB query, tool call payload, etc.). |
| :---- | :---- |
| **`Connector-specific constraints`** | Applies technical constraints specific to the target that are not easily expressible generically in Cedar: rate limits (calls/min to a specific API), response schema validation, format normalisation. Example: an OpenAI connector enforces a 60 req/min rate limit and validates that responses conform to the ChatCompletion schema before passing them back to the agent. |
| **`Normalise audit event`** | Enriches the envelope with call outcome (status, latency, response size) and passes it to the audit emitter. Applies memory namespace tagging. |

| Boundary rule: Stage 2 (CEE) decides policy. The Connector applies target-specific technical constraints that are not conveniently expressible in Cedar. Do not move policy logic into connectors. If a team starts writing business rules inside a connector “because it is easier”, that logic belongs in a Cedar policy and the connector should be refactored. A connector that becomes a second policy engine will break auditability and system guarantees. |
| :---- |

The OSS release includes a generic HTTP connector. Additional connectors (LLM providers, databases, tool APIs) can be contributed as plugins or built privately.

## **8\. Capability Lifecycle**

A capability token has a defined lifecycle. Understanding it is required to build agents that handle revocation and abort correctly.

| `ISSUED` | Authority has created and signed the token. Returned to the Sidecar, not yet validated by Stage 1\. Transient. |
| :---- | :---- |
| **`ACTIVE`** | Stage 1 has validated the token. Session is live. Multi-use: the same token can authorise multiple calls within the session; Stage 2 re-evaluates on every call. |
| **`IN USE`** | Stage 2 passed the current call. A call is actively in-flight. Can return to ACTIVE (session reuse) or advance to EXPIRED / ABORTED. |
| **`EXPIRED`** | Token TTL elapsed. Terminal. The agent must call IssueCapability again to obtain a replacement capability token for subsequent calls that require it. |
| **`REVOKED`** | Authority pushed a revocation signal via WatchRevocations. Terminal. Revocation cache updated immediately. In-flight calls blocked at Stage 1\. |
| **`ABORTED`** | Authority pushed an abort signal via WatchAborts. Terminal. In-flight call terminated immediately. ABORT audit event emitted. |

| Transition ownership: Stage 1 drives ISSUED → ACTIVE. Stage 2 drives ACTIVE → IN USE. TTL drives EXPIRED. The Authority (FA push) drives REVOKED and ABORTED. |
| :---- |

### **8.1  Token Lifecycle vs Session Lifecycle**

These are not the same thing and confusing them leads to incorrect agent behaviour.

| Token lifecycle | Session lifecycle |
| :---- | :---- |
| Managed by Firma (issued, validated, expired, revoked) | Managed by the agent runtime and application |
| TTL is set by Mini Authority (or FA) at IssueCapability time | Session duration is determined by the agent’s task |
| On EXPIRED: agent must call IssueCapability again to obtain a replacement capability token for subsequent calls that require it | On session end: agent disposes the token; FA closes the session context |
| Multi-use: one token covers N calls within its TTL | A session may involve one or more active capability tokens, each scoped independently. Each request is evaluated against the specific capability attached to its Execution Envelope. |
| If token expires while session is live: Stage 1 denies the next call. Agent must re-authenticate. Sidecar does not auto-renew. | If session ends before token expires: token should be explicitly invalidated by calling FA, not left to expire silently |

In V1, the Sidecar does not auto-renew tokens. When Stage 1 returns a DENY with reason TOKEN\_EXPIRED, the agent’s session management code must call IssueCapability again and resume with the new token. Design agent session managers to handle this gracefully.

## **9\. Cedar Policies · Schema · Examples**

Policy content and documentation that make the OSS package usable from day one. Not a runtime component. Without working Cedar files, no one can write policies. Without a getting-started guide, adoption fails at the first README read.

### **9.1  Cedar schema base**

Defines entity types (Agent, Session, Resource, Connector, MemoryNamespace), action types (APICall, ToolUse, MemoryRead, MemoryWrite, etc.), and context attributes that the CEE assembles and makes available at eval time (budget\_remaining, risk\_score, session\_duration\_s, action\_count, etc.). This schema is the stable interface between the Firma runtime and operator-written policies.

### **9.2  Example policies**

| `allow specific API call` | Permit an agent to call a specific endpoint with a specific HTTP method. Starting point for any integration. |
| :---- | :---- |
| **`deny all (default)`** | Default-deny base policy. Every deployment must include this. No other policy → deny. |
| **`memory namespace isolation`** | Prevent cross-namespace memory access. Essential for multi-agent / multi-tenant deployments. Example: Agent A cannot read or write to Agent B’s memory namespace, even if both hold valid capability tokens. |
| **`budget limit policy`** | Deny calls when cumulative token or API-call budget is exceeded. Uses pre-computed context attribute. |
| **`risk threshold policy`** | Deny calls whose static risk attribute exceeds a configured threshold. V1: threshold check only, no dynamic scoring. |

### **9.3  Documentation and contracts**

* Proto / API contracts — canonical .proto definitions for SidecarAuthority gRPC service and ExecutionEvent audit message. Stable boundary between Sidecar and any external system.

* Integration README — step-by-step: connect an agent, write first Cedar policy, read first audit event.

* Getting started guide — zero to running end-to-end demo with firma dev up.

## **10\. Local Dev Mode  ·  firma dev up**

Orchestration command that starts Mini Authority (:50051), Sidecar (:8080), and Example Agent (:8888) in a pre-wired configuration. End-to-end in under 2 minutes, zero cloud dependency.

Features: live Cedar policy hot-reload (edit .cedar while running, bundle pushed to Sidecar automatically), audit log to stdout, and all three example scenarios (ALLOW / DENY / ABORT) runnable immediately.

V1 does not include a web dashboard. The stdout audit log and live Cedar hot-reload are the primary local observability tools. A dashboard is a candidate for a future community contribution.

| Local Dev Mode is the recommended starting point. It makes the full execution pattern observable — pre-flight, Stage 1, Stage 2 / CEE, Connector — before any production integration work begins. |
| :---- |

## **11\. Performance Targets (V1)**

These targets define the expected operating envelope of the Sidecar in a standard single-instance deployment. They serve two purposes: guiding initial implementation decisions, and establishing regression baselines for benchmarking and CI.

| Metric | Target | Notes | Measurement |
| :---- | :---- | :---- | :---- |
| **Stage 1 latency** | **\< 1 ms p95** | Token parse \+ sig verify \+ bloom revoc check. No network I/O. Dominated by ECDSA verify (\~200 µs on commodity hardware). | Benchmark: isolated Stage 1 microbench |
| **Stage 2 latency (CEE)** | **\< 200 µs p95** | Context assembly \+ Cedar eval. Cedar is deterministic; eval time scales with policy complexity. Simple allow/deny rules are \< 50 µs. | Benchmark: Cedar eval with reference policy set |
| **End-to-end overhead** | **\< 3 ms p95** | Total Sidecar-added latency per call: interceptor \+ Stage 1 \+ Stage 2 \+ credential injection \+ audit emit (async). Excludes connector and external system latency. | Measured: agent → Sidecar → connector entry |
| **Memory footprint** | **\< 100 MB RSS** | Includes policy bundle cache, revocation LRU cache, in-flight request state, and audit WAL buffer. Scales with policy bundle size and concurrent session count. | Profiled: steady-state under load |
| **Throughput (single instance)** | **5k – 20k req/s** | Lower bound: conservative Cedar policies, small bundles. Upper bound: simple allow/deny, minimal context. Scales horizontally; each agent process gets its own Sidecar instance. | Load test: wrk2 / ghz against mock connector |
| **Policy bundle hot-reload** | **\< 500 ms** | Time from WatchPolicyBundle push received to CEE using the new bundle. Includes deserialisation and atomic swap. In-flight calls complete against the previous bundle. | Measured: bundle push → first eval with new bundle |
| **Revocation propagation** | **\< 1 s p99** | Time from Authority pushing a revocation event to Stage 1 rejecting the revoked token. Bounded by gRPC stream delivery \+ bloom filter update. | Measured: revoc push → first Stage 1 DENY |

| These targets apply to a standard single-core deployment. They are not hard SLAs for V1. The implementation team should treat them as design constraints and regression gates. If Stage 1 exceeds 1 ms p95 in CI benchmarks, investigate before merging. |
| :---- |

## **12\. Failure Modes**

These are the failure scenarios every team deploying the Sidecar must handle. The decision column states the Sidecar’s default behaviour. Operators can override where noted.

| Failure scenario | Decision | Sidecar behaviour | Notes |
| :---- | :---- | :---- | :---- |
| Mini Authority down at session start | **Fail closed** | IssueCapability RPC fails. Sidecar returns DENY to agent with reason AUTHORITY\_UNAVAILABLE. No token issued, no calls proceed. Agent must retry with backoff. | Expected: FA replaces Mini Auth in prod. Same behaviour. |
| WatchPolicyBundle disconnected — TTL not yet expired | **Continue (degraded)** | Sidecar continues serving requests against the cached bundle. Logs a warning every N seconds. No new calls blocked yet. | Default TTL: 30 s. Configurable. |
| WatchPolicyBundle disconnected — TTL expired | **Fail closed** | Sidecar enters fail-closed mode. All new requests denied with POLICY\_BUNDLE\_STALE. Existing in-flight calls complete. Resumes on stream reconnect. | TTL reset on reconnect \+ first bundle push. |
| WatchRevocations delayed / disconnected | **Continue (degraded)** | Sidecar cannot receive new revocations. Existing cache still valid. Logs warning. Considered acceptable degradation for TTL-bounded window. | Operators can choose fail-closed via config flag. |
| Audit sink unavailable (gRPC) | **WAL buffer** | Events written to local WAL. Sidecar continues accepting calls. WAL replayed when sink reconnects. WAL size capped; if cap exceeded, oldest events are dropped and a counter is emitted. | File / stdout sinks never fail silently. |
| Connector timeout | **Abort in-flight** | Connector returns timeout error. Sidecar emits ABORT audit event, returns CONNECTOR\_TIMEOUT to agent. Token state: IN USE → ACTIVE (call is treated as not completed). | Connector timeout configurable per-connector. |
| Vault / credential injector unavailable | **Fail closed** | Credential injection fails. Call blocked with CREDENTIAL\_INJECTION\_FAILED. Agent receives DENY. No call dispatched to external system. | Basic cred injection from config never fails this way. |

## **13\. V1 Scope Boundary — What is NOT in OSS**

The following capabilities are intentionally excluded from V1. This section exists to prevent teams from building expectations that will be disappointed, and to avoid premature complexity in the OSS codebase.

| `Trust graph` | No dynamic trust relationship modelling between agents, sessions, or principals. Not in Mini Authority, not in the Sidecar. |
| :---- | :---- |
| **`Dynamic risk engine`** | No real-time risk scoring. V1 risk is a static attribute threshold-check. A live risk engine is a Firma Authority (production) capability. |
| **`Multi-tenant control plane`** | Mini Authority is single-tenant, file-based. No per-org policy namespacing, no tenant isolation in the authority layer. |
| **`Compliance-grade audit backend`** | The audit emitter produces signed events. It does not provide a tamper-evident store, replay index, or compliance reporting. FirmaChain covers this in production. |
| **`Enterprise memory governance`** | Memory namespace isolation is provided via Cedar policy. Enterprise-grade memory provenance, lineage tracking, and cross-session memory governance are not in scope. |
| **`Cedar policy compiler / UI`** | The OSS release ships .cedar source files. The F-Control Plane (policy authoring UI, compiler pipeline, bundle distribution) is a proprietary capability. |
| **`Escalation engine`** | No human-in-the-loop escalation path in V1. Agents that require escalation for out-of-policy requests must implement this at the application layer. |
| **`provenance chain (V1)`** | The Execution Envelope schema includes a provenance field, but the V1 runtime does not populate or verify a hash chain. Treat as a reserved, nullable field. |

| For production deployments: replace Mini Authority with Firma Authority (config-only swap), route audit events to FirmaChain, and attach the F-Control Plane for policy authoring and bundle distribution. The Sidecar binary is identical in both environments. |
| :---- |
