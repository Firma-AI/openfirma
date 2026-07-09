# Sidecar Interface Chain

Documents the input and output contracts for each stage of the
`firma-sidecar` enforcement pipeline.

## Overview

Every outbound agent call passes through this chain:

```text
Interceptor -> Normalizer -> Stage 1 -> Stage 2 -> Envelope assembly
```

Each stage short-circuits on failure. A `Deny` or `Passthrough` decision exits
the pipeline immediately.

## Interceptor

**Trait:** `crate::interceptor::Interceptor`

```rust
pub trait Interceptor: Send + Sync + 'static {
    fn run(
        self,
        pipeline: Arc<EnforcementPipeline>,
        cancel: CancellationToken,
    ) -> impl Future<Output = Result<(), InterceptorError>>;
}
```

**Input:** Transport-specific data, such as an HTTP request, gRPC message, or
Unix socket stream.

**Output:** `RawRequest`, a transport-agnostic struct consumed by the
normalizer. HTTP proxy, gRPC hook, and Unix socket modes produce the same
`RawRequest` shape.

**Invariants:**

- Requests that cannot be parsed into a valid `RawRequest` fail closed.
- On `Allow` or `Passthrough`, the interceptor forwards the request upstream.
- On `Deny`, the interceptor returns a structured denial to the caller.
- The interceptor must stop accepting connections and drain in-flight work
  when cancellation is triggered.

## Pipeline Entry Point

**Struct:** `crate::pipeline::EnforcementPipeline`

```rust
pub fn enforce(&self, request: &RawRequest, session_id: &str) -> EnforcementDecision
```

This is the public entry point for enforcement. It runs normalization, Stage 1,
Stage 2, and final envelope assembly in order.

## Normalizer

**Struct:** `crate::normalizer::IntentNormalizer`

```rust
pub fn normalize(
    &self,
    request: &RawRequest,
) -> Result<NormalizedEnvelope, EnforcementDecision>
```

**Input:** `&RawRequest` with method, host, path, headers, body, and TLS flag.

**Output:** `NormalizedEnvelope` containing:

- `intent: ExecutionIntent`, with `action_class` set to a canonical value from
  the v0.1 Action Class Registry.
- `timestamp: DateTime<Utc>`, captured when the request is normalized.

**Failure:** Returns `EnforcementDecision::Deny` when a protected request cannot
be mapped to a known action class or uses an unrecognized HTTP method. Returns
`EnforcementDecision::Passthrough` when the host is not protected.

**Invariants:**

- Classification is deterministic and rule based.
- Sensitive headers such as `authorization`, `cookie`, and `x-api-key` are
  stripped before they enter the envelope.
- Unclassifiable protected actions fail closed.

## Stage 1: Capability Validation

**Struct:** `crate::enforcement::capability_validation::CapabilityValidator`

```rust
pub fn enforce(
    &self,
    envelope: &NormalizedEnvelope,
    session_id: &str,
) -> Result<ValidatedCapability, EnforcementDecision>
```

**Input:** `&NormalizedEnvelope` and session ID.

**Output:** `ValidatedCapability` containing:

- `raw_token: String`, the selected PASETO v4 token.
- `claims: CapabilityClaims`, verified claims extracted from the token.

**Dependencies:**

- `CapabilityMap`, which selects a token by session, action class, and
  resource.
- `TokenVerifier`, which verifies and extracts token claims.
- `RevocationStore`, which checks whether a token ID has been revoked.

**Failure:** Returns `EnforcementDecision::Deny` when token selection fails,
token validation fails, the token is expired, or the token is revoked.

**Invariants:**

- Stage 1 is fully local and does not contact the Authority on the hot path.
- Any validation error maps to `Deny`.

## Stage 2: Constraint Enforcement Engine

**Struct:** `crate::enforcement::constraint_enforcement::ConstraintEnforcer`

```rust
pub fn evaluate(
    &self,
    envelope: &NormalizedEnvelope,
    claims: &CapabilityClaims,
) -> Result<(), EnforcementDecision>
```

**Input:** `&NormalizedEnvelope` and `&CapabilityClaims`.

**Output:** `Ok(())` on success. The pipeline assembles the final
`ExecutionEnvelope` after this stage succeeds.

**Dependency:** `PolicyEvaluation`, which abstracts the policy engine through
`evaluate()`, `is_fresh()`, and `version()`. `evaluate()` takes
`principal: &AgentId, action: &str, resource: &str, context: &serde_json::Value`
and returns `Result<bool, String>`. The production implementation is
`CedarPolicyEvaluator` (fed by `CedarBundleParser` on every accepted
`WatchPolicyBundle` push).

**Steps:**

1. Scope check: verify `action_class` is in the token action set. A wildcard
   `"*"` permits all actions.
2. Bundle freshness: deny when the policy bundle is stale.
3. Context build: assemble policy context from envelope fields, claims, and
   runtime signals.
4. Policy evaluation: evaluate against the current policy bundle.

**Failure:** Returns `EnforcementDecision::Deny` with a sub-stage of
`ScopeCheck`, `BundleFreshness`, or `PolicyEvaluation`.

**Invariants:**

- Same context and same bundle produce the same decision.
- Stage 2 is fully local on the hot path.
- Policy freshness and evaluation errors fail closed.

## Envelope Assembly

On `Allow`, the pipeline assembles an `ExecutionEnvelope` from the
`NormalizedEnvelope`, `ValidatedCapability`, and session context:

```rust
ExecutionEnvelope::new(
    normalized.intent,
    capability.raw_token,
    ExecutionMetadata {
        // session_id is sourced from the VERIFIED token claims, not the
        // caller-supplied header, to prevent session spoofing.
        session_id: capability.claims.session_id.clone(),
        agent_id: capability.claims.agent_id.clone(),
        timestamp: normalized.timestamp,
        trace_id: None,
        budget_consumed: signals.budget_consumed,
        risk_score: if signals.risk_score == 0.0 {
            None
        } else {
            Some(signals.risk_score)
        },
        // AARM R2 G2: server-derived causal context
        thread_id: Some(derive_thread_id(&session_id)),
        parent_action_id: signals.last_provenance.clone(),
    },
    provenance, // AARM R2 G2: hash-chain anchor
)
```

The resulting `ExecutionEnvelope` is structurally immutable. Its fields are
private and exposed through shared-reference getters.

## Decision Type

The pipeline produces exactly one `EnforcementDecision` per evaluated request.
The AARM R4 five-decision set (`ALLOW`, `DENY`, `MODIFY`, `STEP_UP`, `DEFER`)
is required for conformance; `ABORT` is a post-ALLOW local-failure variant and
`PASSTHROUGH` covers non-protected traffic (serialized on the wire as `ALLOW`
with an empty `token_id`). See `crates/firma-sidecar/src/enforcement/decision.rs`
and `crates/firma-protobuf/proto/firma/v1/types.proto` (`EnforcementDecision`).

```rust
pub enum EnforcementDecision {
    Allow {
        claims: CapabilityClaims,
        envelope: Box<ExecutionEnvelope>,
        credentials: InjectedCredentials,
    },
    Deny {
        reason: DenyReason,
        stage: EnforcementStage,
        detail: String,
        envelope: Option<NormalizedEnvelope>,
        identity: Option<DenyIdentity>,
    },
    Abort {
        reason: AbortReason,
        detail: String,
        identity: Option<DenyIdentity>,
    },
    Passthrough {
        detail: String,
    },
    Modify {
        claims: CapabilityClaims,
        envelope: Box<ExecutionEnvelope>,
        modifications: ModificationSpec,
        credentials: InjectedCredentials,
    },
    StepUp {
        claims: Option<CapabilityClaims>,
        envelope: Option<NormalizedEnvelope>,
        challenge: String,
        retry_after_ms: u64,
        identity: Option<DenyIdentity>,
    },
    Defer {
        claims: Option<CapabilityClaims>,
        envelope: Option<NormalizedEnvelope>,
        retry_after_ms: u64,
        identity: Option<DenyIdentity>,
    },
}
```

`MODIFY`, `STEP_UP`, and `DEFER` are sourced from `@modify("…")`, `@step_up("…")`,
and `@defer("…")` Cedar policy annotations on `forbid` policies; the engine
lifts them into `PolicyVerdict` (`constraint_enforcement.rs`) and the pipeline
projects them onto these `EnforcementDecision` variants.

## Data Flow Summary

| Stage       | Input                            | Output                   | On failure          |
| ----------- | -------------------------------- | ------------------------ | ------------------- |
| Interceptor | Transport data                   | `RawRequest`             | Deny                |
| Normalizer  | `&RawRequest`                    | `NormalizedEnvelope`     | Deny or passthrough |
| Stage 1     | `&NormalizedEnvelope`            | `ValidatedCapability`    | Deny                |
| Stage 2     | `&NormalizedEnvelope` and claims | `Ok(())`                 | Deny                |
| Assembly    | Normalized envelope and token    | `Box<ExecutionEnvelope>` | N/A                 |
