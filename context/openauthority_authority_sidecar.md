# **Authority — Sidecar Relationship**

`Internal reference  ·  Cedar eval model  ·  Escalation design  ·  two-phase authorization system`

| This document clarifies one of the most commonly misunderstood points in the OpenAuthority architecture: where Cedar runs, what each component decides, and where escalation (human-in-the-loop) fits. It is written for the engineering team to align terminology before implementation. |
| :---- |

## **1\. The One-Line Answer**

| OpenAuthority is a two-phase authorization system: issuance-time authorization (Authority) and execution-time authorization (Sidecar). The Authority is never on the execution path — all runtime decisions are fully local in the Sidecar.The Authority uses Cedar to decide whether a capability can be issued.The Sidecar uses Cedar to decide whether each individual call is allowed at runtime.Both evaluate Cedar. They answer different questions at different moments. |
| :---- |

Cedar runs in two places. This is not redundant — the two evaluations have fundamentally different inputs, granularity, and timing.

| The two evaluations are not redundant: the Authority limits what is possible, the Sidecar enforces what actually happens. |
| :---- |

## **2\. Two Cedar Evaluations**

The Sidecar is a deterministic, local enforcement engine designed to make per-call decisions without network dependency. It does not originate policy; it executes the policy bundle distributed by the Authority. The Authority is never contacted on the hot path — all runtime enforcement is fully local in the Sidecar.

| 🟣  Authority Cedar eval | 🔵  Sidecar Cedar eval  (Stage 2 / CEE) |
| :---- | :---- |
| **When** | When |
| Once per capability issuance (pre-flight) — at session start or when new capabilities are required during an active session | Once per call, at runtime, every request |
| **Question** | Question |
| "Can this capability exist at all?" | "Can this specific call happen right now?" |
| **Input** | Input |
| Agent identity, requested action set, resource scope, initial session context | Execution Envelope (core protocol unit: intent \+ capability \+ metadata \+ provenance (schema-reserved post-v1)), live runtime state (budget, session history, risk attribute) |
| **Granularity** | Granularity |
| Coarse-grained: decides the permission envelope | Fine-grained: decides each individual call within that envelope |
| **Output** | Output |
| Capability token (scoped, signed, expiring) — or denial | ALLOW  /  DENY *ABORT \= asynchronous in-flight kill signal — not a Cedar evaluation outcome* |
| **Cedar bundle source** | Cedar bundle source |
| Loaded from F-Control Plane (production) or /policies dir (Mini Authority) | Streamed from Authority via WatchPolicyBundle, cached locally — no network call at eval time |

## **3\. What the Authority Actually Does**

The Authority is not just a token vending machine. It performs three roles that are distinct from the Sidecar:

### **3.1  Filters at issuance**

If the agent requests a capability it is not entitled to (wrong agent, disallowed resource, missing context), the Authority rejects at IssueCapability. The token is never created. The Sidecar never has to deal with it. This is the coarse-grained filter that limits the space of valid capabilities before any runtime evaluation begins.

### **3.2  Defines the permission perimeter**

The capability token the Authority issues encodes the boundary within which the Sidecar operates: the allowed action set, the resource scope, the budget ceiling, and the expiry. The Sidecar never allows anything outside this perimeter, regardless of what a Cedar policy might say. The perimeter is cryptographically enforced and cannot be extended or overridden by the Sidecar.

### **3.3  Distributes policy and revocations**

The Authority is the source of truth for both the Cedar policy bundle (pushed via WatchPolicyBundle) and the revocation list (pushed via WatchRevocations). The Sidecar has no independent source of policies. Everything the Sidecar knows about what is allowed came from the Authority. The Sidecar does not originate policy; it executes the policy bundle distributed by the Authority.

| The system is not “Authority decides everything, Sidecar executes”. It is:Authority defines the space of possible actions.Sidecar (Stage 2 / CEE) decides what is permitted within that space, at runtime, for each call. |
| :---- |

## **4\. Concrete Example**

### **Pre-flight — Authority Cedar eval**

Agent requests a capability to use OpenAI. The Authority evaluates with Cedar:

* Agent is in the allowed set?  ✓

* OpenAI is an allowed resource for this agent?  ✓

* Session context is valid?  ✓

Authority issues a capability token:

  `allowed_action_classes: [model.inference.chat]`

  `budget_ceiling:   $100`

  `expiry:           1 hour`

  `scope:            provider.openai.prod`

### **Runtime — Sidecar Cedar eval  (Stage 2 / CEE, per call)**

The agent now makes calls. The Sidecar (Stage 2 / CEE) evaluates each one independently against the Cedar bundle and the current runtime state:

| Call | Sidecar decision |
| :---- | :---- |
| `openai.chat.completions  (budget: $12 used)` | **✓  ALLOW** |
| `openai.images.generate   (policy: not in allowed set)` | **✗  DENY** |
| `openai.chat.completions  (budget: $101 used — ceiling exceeded)` | **✗  DENY** |

All three decisions are made by the Sidecar. The Authority is not contacted. The Sidecar evaluates Cedar locally against the policy bundle it already holds.

## **5\. Escalation and Human-in-the-Loop**

Escalation — where an out-of-policy or ambiguous request is routed to a human for review before proceeding — is an Authority-side concern, not a Sidecar concern. This is a deliberate design choice.

### **5.1  Why escalation belongs to the Authority**

The Sidecar is a local, synchronous, latency-sensitive enforcement engine. Its job is to make a binary decision (ALLOW / DENY) within microseconds. It has no human interaction path, no async workflow, and no persistent state across sessions. Routing an escalation through the Sidecar would break its latency guarantees and its stateless design.

The Authority, by contrast, is the component with the full session context, the trust graph, the risk signals from the Control Plane, and the ability to coordinate async workflows. It is the natural home for "I need a human to review this before I issue the capability."

### **5.2  How escalation will work (future)**

The escalation path starts at IssueCapability. Instead of a binary allow/deny, the Authority will support a third outcome: 

* `ESCALATE` — capability issuance is suspended pending human review.

The flow:

* Agent calls IssueCapability.

* Authority evaluates Cedar. The request is not outright denied, but it triggers an escalation rule (e.g. high-risk resource, unusual action set, low-trust agent).

* Authority returns an ESCALATE response to the Sidecar with a pending session ID.

* The escalation is routed to the appropriate human reviewer (via the F-Control Plane escalation engine).

* If the reviewer approves: Authority issues the capability token and the session resumes.

* If the reviewer denies or times out: the capability is permanently refused for this session.

| The Sidecar never sees the escalation logic. From the Sidecar’s perspective, IssueCapability returns either a capability token or a non-actionable state (DENY / ESCALATE) — in both cases no execution proceeds. The Sidecar has no ESCALATE state. ESCALATE exists only as an IssueCapability outcome and is not part of synchronous Stage 2 decision semantics. Escalation is entirely contained within the Authority → Control Plane → human reviewer loop. |
| :---- |

### **5.3  V1 scope note**

Escalation is not in V1 OSS. Mini Authority returns only ALLOW or DENY at IssueCapability. The escalation engine is a production OpenAuthority Authority capability that requires the F-Control Plane, the risk bus, and the trust graph — none of which are in the OSS release.

The V1 IssueCapability proto reserves a `status` field for this purpose, so the wire format is forward-compatible when escalation is introduced without breaking changes to the Sidecar.

## **6\. Summary**

| OpenAuthority Authority | OpenAuthority Sidecar |
| :---- | :---- |
| Cedar eval at issuance (once per capability — pre-flight) | Cedar eval at runtime (once per call) |
| "Can this capability exist?" | "Can this call happen right now?" |
| Coarse-grained, session-scoped | Fine-grained, call-scoped |
| Defines the permission perimeter (scope, budget, expiry) | Enforces constraints within that perimeter |
| Distributes policy bundle and revocations to Sidecar | Consumes policy bundle; enforces locally |
| Source of escalation and human-in-the-loop (future) | Binary decision engine: ALLOW / DENY only (ABORT is asynchronous — outside Cedar evaluation) |
| Contacted at capability issuance (pre-flight) — never on hot path | Not contacted at runtime — all local |
| Has session context, trust graph, risk signals | Has only what is in the Execution Envelope \+ local state |

