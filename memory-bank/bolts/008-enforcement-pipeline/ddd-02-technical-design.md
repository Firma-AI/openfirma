---
unit: 002-enforcement-pipeline
bolt: 008-enforcement-pipeline
stage: design
status: complete
updated: 2026-04-05T15:30:00Z
---

# Technical Design - Enforcement Pipeline

## Architecture Pattern

**Pipeline pattern** within the Sidecar binary — a sequential chain of stages where each stage either produces a result for the next stage or short-circuits with a DENY decision. This is not a microservice decomposition; it's an in-process pipeline operating on shared memory with zero serialization overhead between stages.

**Rationale**: The enforcement pipeline has strict latency requirements (< 3ms p95 end-to-end). An in-process sequential pipeline with short-circuit semantics is the simplest architecture that meets these requirements. Each stage is a stateless function over shared references — no message passing, no channels, no async coordination.

The pipeline is embedded within the `firma-sidecar` binary crate and depends on `firma-core` for shared types and traits.

---

## Layer Structure

```text
crates/firma-sidecar/src/
│
├── enforcement/                   # ← This unit's module
│   ├── mod.rs                     # Public API: enforce(), re-exports
│   ├── pipeline.rs                # EnforcementPipeline: enforce() orchestration
│   ├── normalizer.rs              # IntentNormalizer: raw request → ExecutionEnvelope
│   ├── stage1.rs                  # Stage1Validator: token validation
│   ├── stage2.rs                  # Stage2Evaluator: Cedar context + policy eval
│   ├── context_builder.rs         # CedarContextBuilder: pure context construction
│   ├── mapping.rs                 # MappingTable, MappingRule, specificity scoring
│   ├── registry.rs                # ActionClassRegistry: v0.1 canonical action classes
│   ├── envelope.rs                # ExecutionEnvelope construction helpers
│   ├── decision.rs                # EnforcementDecision: pipeline result type
│   ├── capability_map.rs           # CapabilityMap: token selection by envelope fields
│   ├── config.rs                  # EnforcementConfig: mapping + stage configuration
│   └── error.rs                   # EnforcementError: internal error types
│
├── lib.rs or main.rs              # Binary entrypoint (outside this unit's scope)
└── ...                            # Other units (proxy-core, audit, etc.)
```

**Module responsibility boundaries**:

| Module | Responsibility | Does NOT do |
|--------|---------------|-------------|
| `pipeline.rs` | Orchestrate stages, short-circuit logic | Stage-specific logic |
| `normalizer.rs` | Match rules, build envelope | Token validation, policy eval |
| `stage1.rs` | Token parse/verify/expiry/revocation | Cedar evaluation, scope check |
| `stage2.rs` | Scope check, Cedar eval | Token validation, normalization |
| `context_builder.rs` | Populate Cedar context attributes | Policy evaluation, side effects |
| `mapping.rs` | Rule matching, specificity scoring | Envelope construction |
| `registry.rs` | Validate action classes | Mapping, evaluation |
| `envelope.rs` | Envelope construction helpers, ActionClass validation | Everything else |

---

## Type Design

### Evolving firma-core Types (ADR-001)

The domain model identified gaps between firma-core's existing types and what the enforcement pipeline needs. Per **ADR-001**, we update firma-core rather than creating sidecar-local duplicates. firma-core is the shared domain library — its types should match the actual domain.

**Changes to firma-core** (implemented during Stage 4):

1. Extend `ExecutionIntent` with three new fields
2. Add `UnclassifiedIntent` to `DenyReason`
3. Keep `PolicyEvaluator` trait as-is (sidecar uses cedar-policy directly)

### ExecutionIntent (firma-core update)

```rust
/// The canonical intent representation — five sub-fields.
/// Immutability enforced by private fields + consuming builder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionIntent {
    action_class: String,      // NEW — canonical action class from registry
    resource: String,          // EXISTS
    params: ActionParams,      // EXISTS
    raw_transport: String,     // NEW — original transport protocol
    raw_action_ref: String,    // NEW — original request signature
}

impl ExecutionIntent {
    // Accessor methods only — no mutation
    pub fn action_class(&self) -> &str { &self.action_class }
    pub fn resource(&self) -> &str { &self.resource }
    pub fn params(&self) -> &ActionParams { &self.params }
    pub fn raw_transport(&self) -> &str { &self.raw_transport }
    pub fn raw_action_ref(&self) -> &str { &self.raw_action_ref }
}

/// Consuming builder — build() takes self, not &self
pub struct ExecutionIntentBuilder { /* fields mirror ExecutionIntent */ }

impl ExecutionIntentBuilder {
    pub fn new(action_class: String, resource: String) -> Self;
    pub fn params(mut self, params: ActionParams) -> Self;
    pub fn raw_transport(mut self, transport: String) -> Self;
    pub fn raw_action_ref(mut self, action_ref: String) -> Self;
    pub fn build(self) -> ExecutionIntent;  // consumes self
}
```

### DenyReason (firma-core update)

```rust
pub enum DenyReason {
    // ... existing variants ...
    #[error("unclassified intent")]
    UnclassifiedIntent,  // NEW — protected action with no mapping
}
```

**Note**: `BudgetExceeded` and `RiskThreshold` remain deferred per intent-plan.md V1 scope exclusions. Budget-based denials come from Cedar as `PolicyDenied`.

### PolicyEvaluator Trait (unchanged)

The firma-core `PolicyEvaluator` trait keeps its simple `evaluate(&ExecutionContext) -> Decision` contract. It remains useful for unit testing and future non-Cedar evaluators. The sidecar's Stage 2 uses `cedar-policy` directly with a richer three-layer context — this is specialization, not a violation of the trait contract.

### ActionClass (registry.rs)

```rust
/// Canonical action class from the v0.1 registry.
/// Validated at construction time — cannot hold an invalid class.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ActionClass(String);

impl ActionClass {
    /// Construct from string, validating against the registry.
    pub fn new(name: &str, registry: &ActionClassRegistry) -> Result<Self, ConfigError>;

    pub fn as_str(&self) -> &str;
}

/// The v0.1 Canonical Action Class Registry.
/// 15 action classes, immutable, defined at compile time.
pub struct ActionClassRegistry {
    classes: HashMap<String, ActionClassDefinition>,
}

pub struct ActionClassDefinition {
    pub name: String,
    pub domain: String,
    pub risk_level: RiskLevel,
}

#[derive(Debug, Clone, Copy)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl ActionClassRegistry {
    /// Build the v0.1 registry with all 15 classes.
    pub fn v0_1() -> Self;

    pub fn contains(&self, name: &str) -> bool;
    pub fn get(&self, name: &str) -> Option<&ActionClassDefinition>;
}
```

### MappingRule and MappingTable (mapping.rs)

```rust
pub struct MappingRule {
    pub method: Option<HttpMethod>,
    pub host_pattern: HostPattern,
    pub path_pattern: PathPattern,
    pub body_fields: Vec<BodyFieldMatcher>,
    pub action_class: ActionClass,
    pub priority: Option<u32>,
    specificity_score: u32,  // computed at load time
}

pub struct HostPattern {
    raw: String,
    is_exact: bool,
    // compiled glob for matching
}

pub struct PathPattern {
    raw: String,
    segments: Vec<PathSegment>,
    // compiled glob for matching
}

pub enum PathSegment {
    Literal(String),
    Wildcard,
}

pub struct BodyFieldMatcher {
    pub json_path: String,
    pub expected_value: Option<String>,
}

pub struct MappingTable {
    rules: Vec<MappingRule>,         // sorted by specificity (descending)
    registry: ActionClassRegistry,
    protected_hosts: HashSet<String>,
    default_protected: bool,
}

impl MappingTable {
    /// Load and validate from config. Fails if:
    /// - Config file missing or malformed
    /// - Any rule references unknown action class
    /// - Duplicate match criteria detected
    pub fn from_config(config: &MappingConfig, registry: ActionClassRegistry)
        -> Result<Self, ConfigError>;

    /// Find the first (most specific) matching rule for a request.
    pub fn find_match(&self, request: &RawRequest) -> Option<&MappingRule>;

    /// Check if a host is in the protected scope.
    pub fn is_protected(&self, host: &str) -> bool;
}
```

### RawRequest (normalizer.rs)

```rust
/// Raw intercepted request — the input to the enforcement pipeline.
/// Constructed by proxy-core from Pingora request data.
pub struct RawRequest<'a> {
    pub method: HttpMethod,
    pub host: &'a str,
    pub path: &'a str,
    pub headers: &'a HeaderMap,
    pub body: Option<&'a [u8]>,    // borrowed, not copied
    pub transport: RawTransport,
}
```

### EnforcementDecision (decision.rs)

```rust
/// Unified pipeline result. Every enforce() call produces exactly one of these.
#[derive(Debug)]
pub enum EnforcementDecision {
    Allow {
        claims: CapabilityClaims,
        envelope: ExecutionEnvelope,
    },
    Deny {
        reason: DenyReason,
        stage: EnforcementStage,
        detail: String,
        envelope: Option<ExecutionEnvelope>,  // None if normalization failed
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementStage {
    Normalization,
    Stage1,
    Stage2,
}

impl EnforcementDecision {
    pub fn is_allow(&self) -> bool;
    pub fn is_deny(&self) -> bool;
    pub fn deny_reason(&self) -> Option<DenyReason>;
    pub fn stage(&self) -> EnforcementStage;
}
```

### DenyReason Extension

firma-core's `DenyReason` enum needs 1 additional variant for enforcement pipeline support:

| New Variant | Usage |
|-------------|-------|
| `UnclassifiedIntent` | Protected action could not be mapped to any action class |

**Deferred per intent-plan.md**: `BudgetExceeded` and `RiskThreshold` remain out of V1 scope. Budget-based denials come through Cedar evaluation as `PolicyDenied`.

---

## API Design

### Public API: enforce()

The single entry point consumed by proxy-core and llm-response-parser.

```rust
/// The enforcement pipeline. Immutable after construction.
/// All methods take &self — safe for concurrent use.
pub struct EnforcementPipeline {
    normalizer: IntentNormalizer,
    stage1: Stage1Validator,
    stage2: Stage2Evaluator,
}

impl EnforcementPipeline {
    /// Construct with all dependencies. Called once at startup.
    pub fn new(
        mapping_table: Arc<MappingTable>,
        capability_map: Arc<CapabilityMap>,
        verifier: Arc<dyn TokenVerifier + Send + Sync>,
        revocation: Arc<dyn RevocationStore + Send + Sync>,
        policy_store: Arc<dyn PolicyBundleStore + Send + Sync>,
        cedar_schema: Arc<CedarSchema>,
        config: Arc<EnforcementConfig>,
    ) -> Self;

    /// Run the full enforcement pipeline.
    /// This is the ONLY public entry point.
    ///
    /// Pipeline: normalize → select token → Stage 1 → Stage 2
    /// Short-circuits on any DENY.
    /// Token is selected internally from the CapabilityMap (ADR-002).
    pub async fn enforce(
        &self,
        request: &RawRequest<'_>,
        session_id: &str,
        session_state: &SessionState,
    ) -> EnforcementDecision;
}
```

**Why `async`**: Although the current implementation is CPU-bound, making `enforce()` async from day one avoids a breaking API change when future extensions add async operations (e.g., remote policy fetch fallback). The runtime cost is negligible — a single poll for a ready future.

### Internal Stage APIs

Each stage is a struct with a single public method. Dependencies are injected at construction time.

```rust
// normalizer.rs
pub struct IntentNormalizer {
    mapping_table: Arc<MappingTable>,
}

impl IntentNormalizer {
    pub fn normalize(&self, request: &RawRequest<'_>)
        -> Result<ExecutionEnvelope, EnforcementDecision>;
}

// stage1.rs
pub struct Stage1Validator {
    verifier: Arc<dyn TokenVerifier + Send + Sync>,
    revocation: Arc<dyn RevocationStore + Send + Sync>,
    clock_skew_tolerance: Duration,
}

impl Stage1Validator {
    pub fn validate(&self, raw_token: &str)
        -> Result<CapabilityClaims, EnforcementDecision>;
}

// stage2.rs
pub struct Stage2Evaluator {
    policy_store: Arc<dyn PolicyBundleStore + Send + Sync>,
    cedar_schema: Arc<CedarSchema>,
    config: Arc<Stage2Config>,
}

impl Stage2Evaluator {
    pub fn evaluate(
        &self,
        envelope: &ExecutionEnvelope,
        claims: &CapabilityClaims,
        session_state: &SessionState,
    ) -> EnforcementDecision;
}
```

**Pattern**: Each stage returns `Result<T, EnforcementDecision>` where Err is always a Deny. The pipeline chains stages with `?`-like short-circuit semantics (mapped via early return).

### Pipeline Flow (pipeline.rs)

```rust
pub async fn enforce(
    &self,
    request: &RawRequest<'_>,
    session_id: &str,
    session_state: &SessionState,
) -> EnforcementDecision {
    // Step 1: Normalize intent
    let envelope = match self.normalizer.normalize(request) {
        Ok(env) => env,
        Err(deny) => return deny,
    };

    // Step 2: Select capability token from map (ADR-002)
    let entry = match self.capability_map.select(
        session_id,
        envelope.intent.action_class(),
        envelope.intent.resource(),
    ) {
        Ok(entry) => entry,
        Err(deny) => return deny,
    };

    // Step 3: Validate selected token (Stage 1)
    let claims = match self.stage1.validate(&entry.raw_token) {
        Ok(claims) => claims,
        Err(deny) => return deny,
    };

    // Step 4: Evaluate policy (Stage 2)
    self.stage2.evaluate(&envelope, &claims, session_state)
}
```

---

## Cedar Integration Design

### Cedar Types Mapping

| Firma Concept | Cedar Concept |
|---------------|---------------|
| Agent (agent_id) | Principal entity |
| ActionClass | Action |
| Resource (normalized resource string) | Resource entity |
| CedarContext attributes | Context record |

### Cedar Entity Schema (.cedarschema)

```cedarschema
// Entity types
entity Agent = {
  session_id: String,
};

entity Target = {};

// Actions — one per action class in v0.1 registry
action "http.get"     appliesTo { principal: Agent, resource: Target };
action "http.post"    appliesTo { principal: Agent, resource: Target };
action "http.put"     appliesTo { principal: Agent, resource: Target };
action "http.delete"  appliesTo { principal: Agent, resource: Target };
action "http.patch"   appliesTo { principal: Agent, resource: Target };
action "db.query"     appliesTo { principal: Agent, resource: Target };
action "db.mutate"    appliesTo { principal: Agent, resource: Target };
action "file.read"    appliesTo { principal: Agent, resource: Target };
action "file.write"   appliesTo { principal: Agent, resource: Target };
action "file.delete"  appliesTo { principal: Agent, resource: Target };
action "code.execute" appliesTo { principal: Agent, resource: Target };
action "system.execute" appliesTo { principal: Agent, resource: Target };
action "network.connect" appliesTo { principal: Agent, resource: Target };
action "messaging.send"  appliesTo { principal: Agent, resource: Target };
action "llm.inference"   appliesTo { principal: Agent, resource: Target };
```

### Context Construction (context_builder.rs)

```rust
pub struct CedarContextBuilder;

impl CedarContextBuilder {
    /// Pure function — no side effects, no I/O.
    pub fn build(
        envelope: &ExecutionEnvelope,
        claims: &CapabilityClaims,
        session_state: &SessionState,
        custom_config: &CustomAttributeConfig,
        agent_metadata: Option<&HeaderMap>,
    ) -> Result<cedar_policy::Context, EvaluationError> {
        let mut attrs = HashMap::new();

        // Base attributes
        attrs.insert("action_class", envelope.action_class().as_str());
        attrs.insert("resource", envelope.resource());
        attrs.insert("agent_id", claims.agent_id.as_str());
        attrs.insert("session_id", claims.session_id.as_str());
        attrs.insert("timestamp", Utc::now().to_rfc3339());

        // Sidecar-managed attributes
        attrs.insert("budget_remaining", session_state.budget_remaining);
        attrs.insert("request_count", session_state.request_count);
        attrs.insert("action_count_window",
            session_state.action_count_for(envelope.action_class()));

        // Trusted custom attributes (from config)
        for (k, v) in &custom_config.trusted {
            attrs.insert(k, v);
        }

        // Untrusted custom attributes (from agent headers, declared only)
        if let Some(headers) = agent_metadata {
            for declared_key in &custom_config.admitted_agent_keys {
                if let Some(value) = headers.get(declared_key) {
                    attrs.insert(declared_key, value);
                }
            }
        }

        cedar_policy::Context::from_pairs(attrs)
    }
}
```

### Cedar Request Construction (stage2.rs)

```rust
fn build_cedar_request(
    envelope: &ExecutionEnvelope,
    claims: &CapabilityClaims,
) -> cedar_policy::Request {
    let principal = EntityUid::from_type_name_and_id(
        "Agent",
        &claims.agent_id,
    );
    let action = EntityUid::from_type_name_and_id(
        "Action",
        envelope.action_class().as_str(),
    );
    let resource = EntityUid::from_type_name_and_id(
        "Target",
        envelope.resource(),
    );

    Request::new(principal, action, resource, context, None)
}
```

### Scope Check (stage2.rs, pre-Cedar gate)

```rust
fn check_scope(
    envelope: &ExecutionEnvelope,
    claims: &CapabilityClaims,
) -> Result<(), EnforcementDecision> {
    let action = envelope.action_class().as_str();

    // Wildcard check: if action_set contains "*", all actions allowed
    if claims.action_set.iter().any(|a| a == "*") {
        return Ok(());
    }

    if !claims.action_set.iter().any(|a| a == action) {
        return Err(EnforcementDecision::Deny {
            reason: DenyReason::ScopeViolation,
            stage: EnforcementStage::Stage2,
            detail: format!(
                "action '{}' not in token's allowed set: {:?}",
                action, claims.action_set
            ),
            envelope: None,
        });
    }

    Ok(())
}
```

---

## Session State Design

```rust
/// Per-session mutable state, accessed via Arc<RwLock<SessionStateMap>>.
pub struct SessionState {
    pub session_id: String,
    pub budget_remaining: f64,
    pub request_count: u64,
    action_windows: HashMap<ActionClass, SlidingWindowCounter>,
}

pub struct SlidingWindowCounter {
    window: Duration,
    entries: VecDeque<Instant>,
}

impl SlidingWindowCounter {
    pub fn count(&self) -> u64;       // count within current window
    pub fn record(&mut self);         // add entry at now
    pub fn prune(&mut self);          // remove expired entries
}

/// Session state map, keyed by session_id.
pub type SessionStateMap = HashMap<String, SessionState>;
```

**Concurrency model**: `Arc<RwLock<SessionStateMap>>` allows concurrent reads during enforcement. Writes (budget decrement, counter increment) happen after the decision is made, not during evaluation. This means Stage 2 reads a potentially slightly stale snapshot — acceptable because:
- Budget decrement on ALLOW is done by the caller post-decision
- Counter increments are best-effort (sliding window tolerates minor imprecision)
- No correctness issue: the pipeline is not transactional

---

## Configuration Design

### TOML Configuration Structure

```toml
[enforcement]
clock_skew_tolerance_seconds = 0    # default: strict

[enforcement.mapping]
config_path = "mapping-rules.toml"  # path to mapping rules file
default_protected = true             # all hosts protected by default

[enforcement.stage2]
cedar_schema_path = "firma.cedarschema"
bundle_ttl_seconds = 30

[enforcement.session]
initial_budget = 1000.0
action_window_seconds = 60

[enforcement.custom_attributes]
# Trusted attributes (from sidecar config)
[enforcement.custom_attributes.trusted]
environment = "production"
tenant_id = "acme-corp"

# Admitted agent metadata keys (from agent headers)
admitted_agent_keys = ["x-firma-context", "x-firma-priority"]
max_attribute_value_bytes = 1024
```

### Mapping Rules File (mapping-rules.toml)

```toml
[[rules]]
host = "api.openai.com"
path = "/v1/chat/completions"
method = "POST"
action_class = "llm.inference"

[[rules]]
host = "api.openai.com"
path = "/v1/embeddings"
method = "POST"
action_class = "llm.inference"

[[rules]]
host = "api.anthropic.com"
path = "/v1/messages"
method = "POST"
action_class = "llm.inference"

[[rules]]
host = "*.googleapis.com"
path = "/v1beta/models/*/generateContent"
method = "POST"
action_class = "llm.inference"

# Generic HTTP passthrough patterns
[[rules]]
host = "*"
method = "GET"
action_class = "http.get"

[[rules]]
host = "*"
method = "POST"
action_class = "http.post"

# ... more rules
```

---

## Security Design

| Concern | Approach |
|---------|----------|
| **Fail-closed discipline** | Every error path in every stage returns DENY. No `unwrap()`, no `panic!()`, no silent pass-through. Errors at internal boundaries are mapped to DenyReason variants. |
| **No bypass path** | `enforce()` is the ONLY path to the connector. There is no "skip enforcement" flag, no debug bypass, no admin override. |
| **Token confidentiality** | Raw token strings are never logged. Token claims (agent_id, session_id, actions) are logged at DEBUG level. Token signature bytes are never exposed. |
| **Credential isolation** | The enforcement pipeline never sees credentials. Credential injection happens after the pipeline returns ALLOW. |
| **Immutable envelope** | ExecutionEnvelope has private fields, no `&mut` accessors, and a consuming builder. Once built, it cannot be modified. |
| **Context isolation** | CedarContextBuilder does not read LLM scratchpads, reasoning traces, prompt windows, or orchestration memory. Agent metadata is admitted only through declared, size-bounded header keys. |
| **Deterministic evaluation** | Cedar evaluation is deterministic by design: same context + same policy set = same result. No randomness, no external calls, no time-dependent logic (timestamp is an attribute, not a decision factor in the evaluator). |
| **system.execute guard** | IntentNormalizer validates that `system.execute` is only produced by explicit mapping rules, never as a fallback for unresolved mappings. This is enforced by the specificity matching algorithm: no-match → UNCLASSIFIED_INTENT, never auto-fallback to system.execute. |

---

## NFR Implementation

| Requirement | Target | Design Approach |
|-------------|--------|-----------------|
| **Stage 1 latency** | < 1ms p95 | All-local validation: PASETO parse + Ed25519 verify + memory-only revocation check (bloom filter + LRU). No I/O, no allocation on hot path (reuse buffers). |
| **Stage 2 latency** | < 200µs p95 | Scope check is a HashSet lookup. Cedar evaluation operates on an in-memory policy set (Arc-wrapped, no copying). Context construction is a pure function with stack-allocated intermediates. |
| **End-to-end overhead** | < 3ms p95 | Pipeline is synchronous in practice (async wrapper for API compatibility). No channels, no task spawning, no message passing between stages. |
| **Concurrency** | Reentrant | All shared state is behind Arc. Policy set and mapping table are immutable (Arc swap on update). RevocationStore uses lock-free bloom filter for reads. SessionState uses RwLock (reads dominate). |
| **Memory** | Bounded | Mapping table is O(rules). Policy set is O(policies). Revocation bloom filter has fixed memory. LRU cache is bounded. No per-request heap allocation on the happy path. |
| **Determinism** | Bit-identical results | Cedar is deterministic. Mapping specificity is deterministic. Token verification is deterministic. No randomness in the pipeline. |

### Benchmarking Strategy

- Microbenchmarks per stage using `criterion`:
  - `bench_normalize_intent` — measure mapping table lookup with varying rule counts
  - `bench_stage1_validate` — measure token parse + verify + revocation check
  - `bench_stage2_evaluate` — measure context build + Cedar eval with varying policy counts
  - `bench_enforce_e2e` — measure full pipeline
- CI regression gate: fail if p95 exceeds target by > 20%

---

## Error Handling

### Error Types (error.rs)

```rust
/// Internal enforcement errors — never exposed to callers.
/// Every variant maps to a DenyReason for the EnforcementDecision.
#[derive(Debug, thiserror::Error)]
pub enum EnforcementError {
    #[error("normalization failed: {detail}")]
    NormalizationFailed {
        detail: String,
        raw_action_ref: Option<String>,
    },

    #[error("token validation failed: {0}")]
    TokenError(#[from] TokenError),

    #[error("policy evaluation failed: {0}")]
    EvaluationError(#[from] EvaluationError),

    #[error("configuration error: {0}")]
    ConfigError(String),
}

impl EnforcementError {
    /// Map any internal error to a DENY decision.
    /// This is the fail-closed boundary.
    pub fn into_deny(self, stage: EnforcementStage) -> EnforcementDecision {
        match self {
            Self::NormalizationFailed { detail, .. } => EnforcementDecision::Deny {
                reason: DenyReason::UnclassifiedIntent,
                stage: EnforcementStage::Normalization,
                detail,
                envelope: None,
            },
            Self::TokenError(e) => EnforcementDecision::Deny {
                reason: token_error_to_deny_reason(&e),
                stage: EnforcementStage::Stage1,
                detail: e.to_string(),
                envelope: None,
            },
            Self::EvaluationError(e) => EnforcementDecision::Deny {
                reason: DenyReason::PolicyDenied,
                stage: EnforcementStage::Stage2,
                detail: e.to_string(),
                envelope: None,
            },
            Self::ConfigError(msg) => EnforcementDecision::Deny {
                reason: DenyReason::MalformedRequest,
                stage,
                detail: msg,
                envelope: None,
            },
        }
    }
}

fn token_error_to_deny_reason(err: &TokenError) -> DenyReason {
    match err {
        TokenError::Expired { .. } => DenyReason::TokenExpired,
        TokenError::Revoked { .. } => DenyReason::TokenRevoked,
        _ => DenyReason::TokenInvalid,
    }
}
```

**Error handling rules**:
- Internal stages use `Result<T, EnforcementError>` for composition
- At the pipeline boundary, all errors are converted to `EnforcementDecision::Deny`
- No `unwrap()` or `expect()` anywhere in the enforcement module
- No `panic!()` — use `EnforcementError::into_deny()` instead
- `thiserror` for all error types (per coding standards)

---

## External Dependencies

| Dependency | Crate | Version | Purpose | Integration |
|------------|-------|---------|---------|-------------|
| firma-core | workspace | - | Types: CapabilityClaims, Decision, DenyReason, TokenError. Traits: TokenVerifier, RevocationStore, PolicyBundleStore | Direct Rust dependency |
| cedar-policy | crates.io | latest stable | Cedar Authorizer, PolicySet, Context, Request, Entities, Schema | Rust crate |
| serde + toml | crates.io | latest stable | Configuration deserialization (mapping rules, enforcement config) | Rust crate |
| sha2 | crates.io | latest stable | SHA-256 for parameters_hash in ExecutionEnvelope | Rust crate |
| chrono | crates.io | latest stable | Timestamp handling, expiry comparison, clock skew | Already in workspace |

### firma-core Trait Usage

| Trait | Method Used | Provided By |
|-------|-------------|-------------|
| `TokenVerifier` | `verify(raw_token) -> Result<CapabilityClaims, TokenError>` | `PasetoV4Verifier` (firma-core) |
| `RevocationStore` | `is_revoked(token_id) -> Result<bool, TokenError>` | Unit 003 implementation |
| `PolicyBundleStore` | `load_bundle()`, `get_version()`, `is_fresh()` | Unit 003 implementation |

---

## Integration Points

### Inbound (callers of this unit)

| Caller | How It Calls | What It Receives |
|--------|-------------|------------------|
| proxy-core (unit 001) | `pipeline.enforce(&raw_request, session_id, &session_state).await` | `EnforcementDecision` → format HTTP response or forward |
| llm-response-parser (unit 004) | `pipeline.enforce(&synthetic_request, session_id, &session_state).await` | `EnforcementDecision` → rewrite or forward LLM response |

### Outbound (dependencies this unit consumes)

| Dependency | What This Unit Reads | Ownership |
|------------|---------------------|-----------|
| TokenVerifier | Verify PASETO tokens | firma-core (via Arc\<dyn\>) |
| RevocationStore | Check bloom filter + LRU | Unit 003 (via Arc\<dyn\>) |
| PolicyBundleStore | Load current Cedar policies | Unit 003 (via Arc\<dyn\>) |
| Mapping rules config | TOML file at startup | This unit loads it |
| Cedar schema | .cedarschema file at startup | This unit loads it |

---

## Token Selection Design (ADR-002)

**Decision**: Sidecar-managed capability map. The agent knows nothing about Firma — it sets `HTTP_PROXY` and makes normal HTTP requests. The sidecar holds multiple capability tokens and selects the correct one after intent normalization.

### CapabilityMap (new module: capability_map.rs)

```rust
/// Holds pre-provisioned capability tokens, selects by envelope fields.
pub struct CapabilityMap {
    tokens: Vec<CapabilityEntry>,
}

pub struct CapabilityEntry {
    pub raw_token: String,
    pub claims: CapabilityClaims,  // pre-parsed at load time
    pub action_set: HashSet<String>,
    pub resource_scope: GlobPattern,
}

impl CapabilityMap {
    /// Select best-matching token for the normalized intent.
    /// Most specific match wins (exact action + specific resource > wildcard).
    /// Returns DENY if no token covers the action.
    pub fn select(
        &self,
        session_id: &str,
        action_class: &str,
        resource: &str,
    ) -> Result<&CapabilityEntry, EnforcementDecision>;
}
```

### Provisioning (dual-mode)

- **File mode**: Pre-signed tokens loaded from config/directory at startup
- **Authority mode**: Sidecar reads capability manifest from config, calls `IssueCapability` per entry at startup, refreshes before expiry

### Pipeline Impact

Token selection sits between normalization and Stage 1:

```text
normalize → select_token → Stage 1 (validate) → Stage 2 (Cedar eval)
```

`enforce()` no longer takes `raw_token` — it takes `session_id` and selects internally.

---

## Testing Strategy Outline

| Test Category | Focus | Approach |
|---------------|-------|----------|
| **Normalizer unit tests** | Rule matching, specificity ordering, all 15 action classes | Property-based: random request + known rules → deterministic result |
| **Stage 1 unit tests** | Token validation sequences (valid, expired, revoked, forged, missing) | Each TokenError variant tested individually |
| **Stage 2 unit tests** | Context building, scope check, Cedar evaluation with real policies | Cedar schema-contract tests: context fields match policy expectations |
| **Pipeline integration tests** | Full enforce() path: normalize → Stage 1 → Stage 2 | Test each short-circuit path + happy path |
| **Fail-closed tests** | Every error path ends in DENY | Exhaustive error injection: missing config, malformed token, empty policy set, stale bundle |
| **Performance benchmarks** | Latency targets per stage | criterion benchmarks with CI regression gates |
| **Determinism tests** | Same inputs → same outputs | Run enforce() 1000x with identical inputs, assert identical results |
