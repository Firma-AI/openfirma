---
unit: 002-enforcement-pipeline
bolt: 008-enforcement-pipeline
stage: model
status: complete
updated: 2026-04-05T14:30:00Z
---

# Static Model - Enforcement Pipeline

## Bounded Context

The **Enforcement Pipeline** is the core decision engine of the Firma Sidecar. Every intercepted request — whether on the request path (proxy-core) or the response path (LLM tool call evaluation) — passes through this pipeline. It transforms a raw intercepted request into a canonical representation, validates the agent's capability token, evaluates Cedar authorization policies, and returns a binary ALLOW/DENY decision.

The pipeline is stateless with respect to individual requests: all mutable state (session counters, policy bundles, revocation caches) is accessed via shared references. The pipeline never contacts the Authority at evaluation time — all validation is fully local.

**Key invariant**: Every code path through the pipeline terminates in either ALLOW or DENY. There is no pass-through, no silent failure, no panic-as-denial. This is the fail-closed discipline.

**Consumers**: proxy-core (request-path enforcement), llm-response-parser (response-path tool call enforcement).

---

## Domain Entities

### MappingTable

The ordered, validated collection of mapping rules that powers intent normalization. Loaded from TOML configuration at startup. Immutable after initialization (no hot-reload in V1).

| Property | Type | Description |
|----------|------|-------------|
| rules | Vec\<MappingRule\> | Ordered by specificity (most specific first) |
| registry | ActionClassRegistry | Valid action classes for rule validation |
| protected_hosts | Set\<HostPattern\> | Hosts that require enforcement (configurable) |

**Business Rules**:
- Rules are validated at load time: every rule must reference a known action class from the registry
- Duplicate rules (identical match criteria) are rejected at load time
- Rules with empty or null action_class are rejected at load time
- If the configuration file is missing or malformed, the Sidecar refuses to start (fail-fast)
- Rule ordering is deterministic: specificity score computed from (exact host > wildcard host, longest path prefix, method specificity, body field count)

### ActionClassRegistry

The v0.1 Canonical Action Class Registry. Defines the bounded vocabulary of canonical actions that the enforcement pipeline understands.

| Property | Type | Description |
|----------|------|-------------|
| classes | Map\<String, ActionClassDefinition\> | All registered action classes keyed by canonical name |
| version | String | Registry version identifier (e.g., "v0.1") |

**v0.1 Registry — 15 Action Classes**:

| Action Class | Domain | Risk | Description |
|--------------|--------|------|-------------|
| `http.get` | Network | Low | Read data via HTTP GET |
| `http.post` | Network | Medium | Submit or create data via HTTP POST |
| `http.put` | Network | Medium | Replace data via HTTP PUT |
| `http.delete` | Network | High | Delete data via HTTP DELETE |
| `http.patch` | Network | Medium | Partial update via HTTP PATCH |
| `db.query` | Database | Low | Read-only database query |
| `db.mutate` | Database | High | Database write operation (insert/update/delete) |
| `file.read` | File I/O | Low | Read file or object content |
| `file.write` | File I/O | Medium | Write, create, or modify file/object |
| `file.delete` | File I/O | High | Delete file or object |
| `code.execute` | Execution | High | Execute code in a managed/sandboxed runtime |
| `system.execute` | Execution | Critical | Raw shell/system command execution — bounded high-risk fallback only |
| `network.connect` | Network | Medium | Establish arbitrary network connection (WebSocket, TCP, etc.) |
| `messaging.send` | Communication | Medium | Send message (email, Slack, SMS, webhook) |
| `llm.inference` | AI/LLM | Low | LLM completion, chat, or embedding call |

**Business Rules**:
- `system.execute` must NOT be used as a convenience fallback for unresolved mappings — it is reserved exclusively for genuinely ambiguous raw execution surfaces (e.g., a shell command body)
- Every action class has a canonical string identifier (dot-delimited: `{domain}.{verb}`)
- The registry is immutable at runtime (defined at compile time for V1)
- Mapping rules may only reference action classes present in the registry

### SidecarState

Mutable per-session state tracked by the Sidecar, used by Stage 2 context building.

| Property | Type | Description |
|----------|------|-------------|
| session_id | String | The session this state belongs to |
| budget_remaining | f64 | Generic budget counter (decremented per action, configurable initial value) |
| request_count | u64 | Monotonic counter per session |
| action_count_windows | Map\<ActionClass, SlidingWindowCounter\> | Per-action-class sliding window counters |

**Business Rules**:
- State is per-session, not per-request
- Budget is decremented on ALLOW decisions (not at evaluation time)
- Sliding window counters track invocation frequency per action class within a configurable time window
- State is accessed via shared reference (Arc\<RwLock\>) for concurrent reads

---

## Value Objects

### ActionClass

A canonical action class from the v0.1 registry. Transport-agnostic representation of what an agent intends to do.

| Property | Type | Constraints |
|----------|------|-------------|
| name | String | Must match `{domain}.{verb}` format, must be in the registry |

### MappingRule

A single rule that maps raw HTTP request patterns to a canonical action class.

| Property | Type | Constraints |
|----------|------|-------------|
| method | Option\<HttpMethod\> | HTTP method to match (None = any method) |
| host_pattern | HostPattern | Glob pattern for target host (e.g., `*.openai.com`, `api.anthropic.com`) |
| path_pattern | PathPattern | Glob/prefix pattern for request path (e.g., `/v1/chat/completions`, `/v1/*/completions`) |
| body_fields | Option\<Vec\<BodyFieldMatcher\>\> | Optional matchers on JSON body fields |
| action_class | ActionClass | The canonical action class this rule maps to |
| priority | Option\<u32\> | Explicit priority for tie-breaking (lower = higher priority) |

**Specificity Resolution** (deterministic, most specific wins):
1. Exact host > wildcard host
2. Longest path prefix
3. More body_field matchers > fewer
4. Explicit method > any method
5. Lower priority number > higher
6. If still tied: config load order (first rule wins)

### HostPattern

A pattern for matching target hosts.

| Property | Type | Constraints |
|----------|------|-------------|
| pattern | String | Exact string or glob with `*` wildcard (e.g., `*.openai.com`) |
| is_exact | bool | Whether this is an exact match (no wildcards) |

### PathPattern

A pattern for matching URL paths.

| Property | Type | Constraints |
|----------|------|-------------|
| pattern | String | Path prefix or glob pattern (e.g., `/v1/chat/*`, `/v1/messages`) |
| segments | Vec\<PathSegment\> | Parsed segments for specificity scoring |

### BodyFieldMatcher

Matches a specific field in a JSON request body.

| Property | Type | Constraints |
|----------|------|-------------|
| json_path | String | Dot-delimited path to the JSON field (e.g., `model`, `tools.0.type`) |
| expected_value | Option\<String\> | Expected value (None = field must exist regardless of value) |

### RawRequest

The raw intercepted request as received by the proxy, before any normalization.

| Property | Type | Constraints |
|----------|------|-------------|
| method | HttpMethod | The HTTP method |
| host | String | Target host from the request |
| path | String | Request path |
| headers | Map\<String, String\> | Request headers |
| body | Option\<BodyRef\> | Reference to request body (lazy-parsed, may be large) |
| transport | String | Transport protocol (`http` or `https`) |

### ExecutionEnvelope / ExecutionIntent (firma-core, evolved per ADR-001)

The result of successful intent normalization. The `ExecutionIntent` contains five canonical intent sub-fields. **Immutable after creation** — enforced by private fields with no `&mut` accessors, built via a consuming builder in firma-core.

| Property | Type | Constraints |
|----------|------|-------------|
| action_class | String | Canonical action class from the registry |
| resource | String | Normalized resource identifier (e.g., `api.openai.com/v1/chat/completions`) |
| params | ActionParams | Request parameters |
| raw_transport | String | Original transport protocol (`http`, `https`) |
| raw_action_ref | String | Original request signature (e.g., `POST /v1/chat/completions`) for traceability |

**Note**: Per ADR-001, these fields are added to firma-core's `ExecutionIntent` directly. No sidecar-local duplicate types.

### CedarContext

The context object passed to Cedar for policy evaluation. Three layers of attributes.

| Property | Type | Constraints |
|----------|------|-------------|
| base_attributes | BaseAttributes | Derived from NormalizedEnvelope + verified claims |
| sidecar_attributes | SidecarAttributes | Computed from SidecarState |
| custom_attributes | CustomAttributes | Operator-defined, split by trust level |
| schema_version | String | Cedar schema version for audit |

#### BaseAttributes (from envelope + token claims)

| Attribute | Source | Type |
|-----------|--------|------|
| action_class | NormalizedEnvelope | String |
| resource | NormalizedEnvelope | String |
| agent_id | CapabilityClaims | String |
| session_id | CapabilityClaims | String |
| timestamp | Wall clock (UTC) | DateTime |

#### SidecarAttributes (from SidecarState)

| Attribute | Source | Type |
|-----------|--------|------|
| budget_remaining | SidecarState | f64 |
| request_count | SidecarState | u64 |
| action_count_window | SidecarState per action_class | u64 |

#### CustomAttributes (operator-defined)

| Category | Source | Trust Level | Admission |
|----------|--------|-------------|-----------|
| Trusted | Sidecar configuration | Trusted | Always admitted |
| Untrusted | Agent-supplied metadata headers | Untrusted | Only if declared in config |

**Business Rules**:
- Attribute schema is driven by `.cedarschema`, not hardcoded
- Undeclared agent-supplied metadata keys are dropped silently
- Oversized attribute values are truncated or dropped per configuration
- Context Builder must NOT read LLM scratchpads, reasoning traces, prompt windows, or orchestration memory
- Context Builder is a pure function: (NormalizedEnvelope, VerifiedClaims, SidecarState, Config) → CedarContext

### EnforcementDecision

The unified result of the entire enforcement pipeline. Carries everything callers need.

| Variant | Properties | Description |
|---------|------------|-------------|
| Allow | verified_claims: CapabilityClaims, envelope: NormalizedEnvelope | Request is authorized; proceed to credential injection + connector |
| Deny | reason: DenyReason, stage: EnforcementStage, detail: String, raw_transport: Option\<String\>, raw_action_ref: Option\<String\> | Request denied; construct denial response |

### EnforcementStage

Identifies which pipeline stage produced a decision.

| Variant | Description |
|---------|-------------|
| Normalization | Intent normalization (pre-Stage-1) |
| Stage1 | Token validation |
| Stage2 | Cedar policy evaluation |

### ProtectedScope

Configurable definition of which requests require enforcement.

| Property | Type | Constraints |
|----------|------|-------------|
| protected_hosts | Set\<HostPattern\> | Hosts that require full pipeline enforcement |
| default_protected | bool | Whether unlisted hosts are protected by default |

**Business Rules**:
- Non-protected requests (e.g., health checks, OPTIONS preflight) may passthrough or follow default policy per configuration
- By default, all actions routed through the enforcement pipeline are considered protected

### SlidingWindowCounter

Tracks invocation count per action class within a configurable time window.

| Property | Type | Constraints |
|----------|------|-------------|
| window_duration | Duration | Configurable window size |
| count | u64 | Number of invocations in current window |
| window_start | DateTime | Start of current window |

---

## Aggregates

### EnforcementPipeline (Aggregate Root)

The primary aggregate. Orchestrates the full two-phase enforcement pipeline through a single `enforce()` entry point.

| Member | Role | Invariant |
|--------|------|-----------|
| IntentNormalizer | Maps raw request → NormalizedEnvelope | Must produce deterministic results |
| Stage1Validator | Validates capability token | Must complete < 1ms p95 |
| Stage2Evaluator | Builds Cedar context, checks scope, evaluates policies | Must complete < 200µs p95 |

**Aggregate Invariants**:
- Every `enforce()` call returns either ALLOW or DENY — no other outcome is possible
- Stage 1 failure short-circuits: Stage 2 is never invoked
- Normalization failure short-circuits: neither Stage 1 nor Stage 2 is invoked
- The pipeline is reentrant: concurrent `enforce()` calls do not interfere
- Total pipeline overhead < 3ms p95

### MappingTable (Aggregate Root)

Manages the collection of mapping rules and validates them against the registry.

| Member | Role | Invariant |
|--------|------|-----------|
| rules: Vec\<MappingRule\> | Ordered mapping rules | Deterministic ordering by specificity |
| registry: ActionClassRegistry | Valid action classes | All rule action_classes must be in registry |
| protected_scope: ProtectedScope | Enforcement scope | Defines which requests are protected |

**Aggregate Invariants**:
- Every rule references a valid action class from the registry
- No duplicate rules (identical match criteria)
- Rule ordering is deterministic and computable from rule properties
- Missing or malformed config → fail-fast (no partial initialization)

---

## Domain Events

| Event | Trigger | Payload |
|-------|---------|---------|
| IntentNormalized | Raw request successfully mapped to action class | action_class, resource, raw_action_ref |
| IntentUnclassified | Protected action could not be mapped | raw_transport, raw_action_ref, detail |
| TokenValidated | Stage 1 passed all checks | token_id, agent_id, session_id |
| TokenRejected | Stage 1 failed (invalid/expired/revoked) | token_id (if parseable), reason_code |
| PolicyEvaluated | Stage 2 completed (ALLOW or DENY) | decision, action_class, resource, bundle_version |
| ScopeViolation | Action not in token's allowed action set | action_class, token_actions |
| EnforcementCompleted | Full pipeline completed | decision, enforcement_latency_us, stage |

**Note**: These are logical domain events consumed by the audit subsystem (unit 006). They are not emitted via a message bus — they are converted to `ExecutionEvent` audit records by the caller.

---

## Domain Services

### IntentNormalizer

Maps a `RawRequest` to a `NormalizedEnvelope` using the `MappingTable`. Returns `DENY: UNCLASSIFIED_INTENT` for protected actions that cannot be deterministically classified.

| Operation | Inputs | Output | Error |
|-----------|--------|--------|-------|
| normalize | RawRequest, &MappingTable | NormalizedEnvelope | DENY: UNCLASSIFIED_INTENT |

**Algorithm**:
1. Check if request host is in protected scope
2. If not protected: return passthrough signal (caller decides behavior)
3. Iterate rules in specificity order, find first match
4. If no match and host is protected: DENY: UNCLASSIFIED_INTENT
5. If match found: build NormalizedEnvelope with the rule's action_class
6. Validate that `system.execute` is not used as a convenience fallback (rule must explicitly map to it)

**Dependencies**: MappingTable (loaded at startup)

### Stage1Validator

Validates the capability token. Fully local — no Authority contact.

| Operation | Inputs | Output | Error |
|-----------|--------|--------|-------|
| validate | raw_token: &str, verifier: &dyn TokenVerifier, revocation: &dyn RevocationStore | CapabilityClaims | DENY: TOKEN_INVALID / TOKEN_EXPIRED / TOKEN_REVOKED |

**Validation sequence** (order matters — fail at first check):
1. Parse PASETO v4 token structure
2. Verify Ed25519 cryptographic signature against Authority public key
3. Extract claims (token_id, agent_id, session_id, action_set, resource_scope, expiry)
4. Check expiry: if `expiry <= now` (configurable clock skew tolerance), DENY: TOKEN_EXPIRED
5. Check revocation via RevocationStore: bloom filter negative = definitively not revoked; bloom filter positive → check LRU; LRU hit = DENY: TOKEN_REVOKED; LRU miss = not revoked

**Dependencies**: TokenVerifier (firma-core trait, PasetoV4Verifier impl), RevocationStore (firma-core trait, impl in unit 003)

### Stage2Evaluator

Builds Cedar context, performs scope check, evaluates Cedar policies.

| Operation | Inputs | Output | Error |
|-----------|--------|--------|-------|
| evaluate | envelope: &NormalizedEnvelope, claims: &CapabilityClaims, state: &SidecarState, policy_bundle: &PolicyBundle, config: &StageConfig | Decision | DENY: SCOPE_VIOLATION / POLICY_DENIED / BUDGET_EXCEEDED / POLICY_BUNDLE_STALE |

**Evaluation sequence**:
1. **Pre-gate: Scope check** — verify `envelope.action_class` is in `claims.action_set`. If not: DENY: SCOPE_VIOLATION (Cedar is never invoked)
2. **Build CedarContext** via CedarContextBuilder (pure function)
3. **Check policy bundle freshness** — if TTL expired: DENY: POLICY_BUNDLE_STALE
4. **Evaluate Cedar policies** — pass CedarContext + policy set to Cedar Authorizer
5. Return Cedar's decision: ALLOW or DENY: POLICY_DENIED

**Dependencies**: PolicyBundleStore (firma-core trait, impl in unit 003), Cedar Authorizer (cedar-policy crate)

### CedarContextBuilder

Pure function that constructs the Cedar evaluation context from its inputs. No side effects, no I/O.

| Operation | Inputs | Output |
|-----------|--------|--------|
| build | envelope: &NormalizedEnvelope, claims: &CapabilityClaims, state: &SidecarState, config: &ContextConfig | CedarContext |

**Attribute population**:
1. Base attributes from envelope + claims: action_class, resource, agent_id, session_id, timestamp
2. Sidecar-managed from SidecarState: budget_remaining, request_count, action_count_window
3. Trusted custom from config: deployment-level key-value pairs
4. Untrusted custom from agent metadata headers: only admitted if declared in config; undeclared keys dropped

### EnforcementOrchestrator

The `enforce()` entry point. Wires IntentNormalizer → Stage1Validator → Stage2Evaluator with short-circuit semantics.

| Operation | Inputs | Output |
|-----------|--------|--------|
| enforce | raw_request: RawRequest, raw_token: &str, shared_state: &SharedEnforcementState | EnforcementDecision |

**SharedEnforcementState** bundles all shared references:
- mapping_table: &MappingTable
- verifier: &dyn TokenVerifier
- revocation: &dyn RevocationStore
- policy_bundle: &PolicyBundleStore
- sidecar_state: &SidecarState
- config: &EnforcementConfig

**Pipeline flow**:
```
RawRequest + Token
       │
       ▼
┌──────────────────┐     DENY: UNCLASSIFIED_INTENT
│ IntentNormalizer  │────────────────────────────────► EnforcementDecision::Deny
│ (normalize)      │
└────────┬─────────┘
         │ NormalizedEnvelope
         ▼
┌──────────────────┐     DENY: TOKEN_INVALID/EXPIRED/REVOKED
│ Stage1Validator   │────────────────────────────────► EnforcementDecision::Deny
│ (validate)       │
└────────┬─────────┘
         │ CapabilityClaims
         ▼
┌──────────────────┐     DENY: SCOPE_VIOLATION/POLICY_DENIED/BUDGET_EXCEEDED
│ Stage2Evaluator   │────────────────────────────────► EnforcementDecision::Deny
│ (evaluate)       │
└────────┬─────────┘
         │
         ▼
EnforcementDecision::Allow { claims, envelope }
```

---

## Repository Interfaces

| Repository | Entity | Methods |
|------------|--------|---------|
| MappingTableLoader | MappingTable | `load(config_path) -> Result<MappingTable, ConfigError>` |
| PolicyBundleStore | PolicyBundle | `load_bundle() -> Result<PolicyBundle>`, `get_version() -> Option<String>`, `is_fresh() -> bool` (firma-core trait) |
| RevocationStore | Revocation cache | `is_revoked(token_id) -> Result<bool>` (firma-core trait) |

**Note**: PolicyBundleStore and RevocationStore are defined in firma-core and implemented by unit 003-policy-revocation. This unit consumes them via trait references.

---

## Ubiquitous Language

| Term | Definition |
|------|------------|
| **Action Class** | A canonical, transport-agnostic classification of what an agent intends to do (e.g., `http.get`, `db.mutate`, `system.execute`). From the v0.1 Canonical Action Class Registry. |
| **Intent Normalization** | The deterministic process of mapping a raw intercepted request into a canonical NormalizedEnvelope with an action_class from the registry. |
| **Normalized Envelope** | The immutable canonical representation of an intercepted request after normalization. Contains action_class, resource, parameters, raw_transport, raw_action_ref. |
| **Mapping Rule** | A configuration entry that matches raw request patterns (method, host, path, body fields) to a canonical action class. |
| **Mapping Table** | The ordered, validated collection of mapping rules loaded from TOML configuration at startup. |
| **Protected Scope** | The set of hosts/actions that require enforcement. Requests outside the protected scope may passthrough without enforcement. |
| **Unclassified Intent** | A protected action that cannot be deterministically mapped to any canonical action class. Always results in DENY. |
| **Stage 1** | First enforcement phase: capability token validation (parse, verify, expiry, revocation). Fully local, no Authority contact. Target: < 1ms p95. |
| **Stage 2** | Second enforcement phase: Cedar context building, scope check, and policy evaluation. Target: < 200µs p95. |
| **Scope Check** | A pre-Cedar gate in Stage 2 that validates the current action_class is within the capability token's allowed action set. |
| **Cedar Context** | The attribute object passed to Cedar for policy evaluation. Three layers: base (from envelope/claims), sidecar-managed (from local state), operator-custom (from config + agent metadata). |
| **Short-Circuit** | Pipeline behavior where a failure at any stage immediately returns DENY without invoking subsequent stages. |
| **Fail-Closed** | Design discipline where any error, uncertainty, or missing data results in DENY, never in a silent pass-through or panic. |
| **Enforcement Decision** | The unified binary result of the pipeline: ALLOW (with verified claims + envelope) or DENY (with reason code, stage, and detail). |
| **Capability Token** | A PASETO v4 token issued by the Authority that grants an agent specific capabilities (actions, resources) for a session. |
| **Revocation Cache** | A two-layer cache (bloom filter + LRU) for O(1) token revocation checks. Populated by unit 003, read by Stage 1. |
| **Policy Bundle** | The current set of Cedar policies loaded from file or gRPC. Immutable once loaded (Arc-wrapped). Swapped atomically on update. |
| **Bundle Freshness (TTL)** | Policy bundles have a TTL. If the TTL expires without successful refresh, the Sidecar enters fail-closed mode (DENY all: POLICY_BUNDLE_STALE). |
| **system.execute** | The highest-risk action class, reserved for genuinely ambiguous raw execution surfaces. Must never be used as a convenience fallback for unresolved mappings. |
| **Deterministic Evaluation** | The guarantee that the same Cedar context + the same policy bundle produces the same decision every time. |

---

## Story Coverage Matrix

| Domain Concept | Story 001 | Story 002 | Story 003 | Story 004 | Story 005 |
|----------------|-----------|-----------|-----------|-----------|-----------|
| ActionClassRegistry | Primary | Consumed | - | - | - |
| MappingTable / MappingRule | Primary | Consumed | - | - | - |
| IntentNormalizer | Primary | Primary | - | - | Consumed |
| NormalizedEnvelope | Primary | - | - | Consumed | Consumed |
| ProtectedScope | Consumed | Primary | - | - | - |
| Stage1Validator | - | - | Primary | - | Consumed |
| CapabilityClaims | - | - | Primary | Consumed | Consumed |
| RevocationStore (trait) | - | - | Consumed | - | - |
| CedarContext / CedarContextBuilder | - | - | - | Primary | Consumed |
| SidecarState | - | - | - | Primary | - |
| Stage2Evaluator | - | - | - | Primary | Consumed |
| ScopeCheck | - | - | - | Primary | Consumed |
| EnforcementOrchestrator | - | - | - | - | Primary |
| EnforcementDecision | Produced | Produced | Produced | Produced | Primary |

---

## Design Gaps and Open Questions

### Resolved: ExecutionEnvelope Type Evolution (ADR-001)

Per **ADR-001** (accepted): firma-core's `ExecutionIntent` will be extended with `action_class`, `raw_transport`, and `raw_action_ref`. The enforcement pipeline uses firma-core types directly — no sidecar-local duplicates. `DenyReason` gains `UnclassifiedIntent`. See `bolts/008-enforcement-pipeline/adr-001-evolve-firma-core-types.md`.

### Resolved: Token Discovery (ADR-002)

Per **ADR-002** (accepted): Sidecar-managed capability map. Agent knows nothing about Firma. Sidecar holds multiple tokens, selects by (session_id, action_class, resource) after normalization. Dual-mode: file for dev, Authority for production. See `bolts/008-enforcement-pipeline/adr-002-capability-map-token-selection.md`.

### Open Question: Cedar Entity Schema

The exact Cedar entity schema for V1 (entity types, action types, context attribute definitions) is designed during Technical Design. The domain model defines the attribute categories (base, sidecar-managed, custom) but not the concrete `.cedarschema` content.
