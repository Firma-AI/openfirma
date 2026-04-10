---
bolt: 008-enforcement-pipeline
created: 2026-04-05T16:30:00Z
status: accepted
superseded_by: null
---

# ADR-001: Evolve firma-core types to match enforcement pipeline requirements

## Context

During construction of bolt 008-enforcement-pipeline, the domain model and technical design identified significant gaps between firma-core's existing types and what the enforcement pipeline actually needs:

1. **ExecutionEnvelope** is missing three of the five canonical intent sub-fields: `action_class`, `raw_transport`, `raw_action_ref`. The enforcement pipeline requires all five for normalization, policy evaluation, and audit.

2. **ExecutionContext** (used by `PolicyEvaluator` trait) only carries 7 fields. The Cedar evaluation context needs 10+ attributes across three layers (base, sidecar-managed, operator-custom).

3. **DenyReason** is missing `UnclassifiedIntent` — a pre-Stage-1 denial code produced when protected actions cannot be mapped to a canonical action class.

The initial technical design proposed creating sidecar-local duplicate types (`NormalizedEnvelope`) to avoid modifying firma-core. This would mean firma-core's primary consumer (the sidecar) doesn't use its shared types — defeating the purpose of the shared library.

## Decision

Update firma-core's existing types to serve the enforcement pipeline's actual requirements, rather than creating sidecar-local duplicates. Keep `PolicyEvaluator` trait simple and have the sidecar use `cedar-policy` directly for rich context evaluation.

### Specific Changes

**1. Extend `ExecutionIntent` with missing sub-fields:**

```rust
pub struct ExecutionIntent {
    pub action_class: String,    // NEW — canonical action class from registry
    pub resource: String,        // EXISTS
    pub params: ActionParams,    // EXISTS
    pub raw_transport: String,   // NEW — original transport protocol (http/https)
    pub raw_action_ref: String,  // NEW — original request signature for traceability
}
```

**2. Add `UnclassifiedIntent` to `DenyReason`:**

```rust
pub enum DenyReason {
    // ... existing variants ...
    #[error("unclassified intent")]
    UnclassifiedIntent,          // NEW
}
```

**3. Keep `PolicyEvaluator` trait as-is:**

The trait's simple `evaluate(&ExecutionContext) -> Decision` interface remains useful for:
- Unit testing with mock evaluators
- Future non-Cedar evaluators (OPA, custom engines)
- Simple policy evaluation that doesn't need rich context

The sidecar's Stage 2 uses `cedar-policy` directly with a richer context. This is not a violation — it's specialization. The trait provides a simple contract; the sidecar needs more.

**4. Enforce immutability via builder pattern:**

`ExecutionEnvelope` retains private fields + consuming builder. The builder lives in firma-core. The sidecar's `IntentNormalizer` uses the builder to construct envelopes.

## Rationale

- firma-core is the shared domain library — its types should reflect the actual domain model
- The enforcement pipeline IS the core domain; if its types differ from firma-core's, firma-core is wrong
- The types were designed during intent 002 before the detailed enforcement pipeline existed — evolution is expected
- Sidecar-local duplicates create mapping overhead, confusion, and divergence risk
- Updating firma-core is a smaller change than maintaining parallel type hierarchies

### Alternatives Considered

| Alternative | Pros | Cons | Why Rejected |
|-------------|------|------|--------------|
| Sidecar-local `NormalizedEnvelope` | No firma-core changes; no risk to existing code | Primary consumer ignores shared types; mapping overhead; types diverge over time | Defeats the purpose of a shared type library |
| Wrapper type around `ExecutionEnvelope` | Extends without modifying firma-core | Extra indirection; partial duplication; confusing which type to use | Adds complexity without solving the fundamental problem |
| Generic `ExecutionEnvelope<C>` with context type param | Maximum flexibility | Over-engineering for V1; generic type params infect all consumers | YAGNI — only one concrete context type exists |

## Consequences

### Positive

- Single source of truth for execution types — no sidecar-local duplicates
- firma-core types accurately represent the domain as designed by the enforcement pipeline
- Builder pattern in firma-core means all consumers benefit from immutability enforcement
- Simpler sidecar code — uses firma-core types directly, no adapters

### Negative

- Requires updating existing firma-core tests that construct `ExecutionIntent` / `ExecutionEnvelope`
- Adds a new `DenyReason` variant — existing match statements need updating (compiler enforces this)
- Intent 002 bolt artifacts (domain model, technical design) are now partially outdated

### Risks

- Existing code in intents 001-004 may reference the old `ExecutionIntent` shape. Mitigation: compiler errors will flag every usage; changes are additive (new fields), not destructive (no removed fields).
- If future interception modes (eBPF, gRPC) need different intent sub-fields, `ExecutionIntent` may need further evolution. Mitigation: the five sub-fields are transport-agnostic by design — `raw_transport` and `raw_action_ref` capture the original transport without constraining it.

## Related

- **Stories**: All 5 stories in bolt 008 (001-intent-normalizer through 005-two-phase-pipeline-integration)
- **Standards**: `tech-stack.md` — no change needed (types, not dependencies)
- **Previous ADRs**: ADR-001 in bolt 003-paseto-v4 (pasetors choice — complementary, not conflicting)
- **Scope note**: `BudgetExceeded` and `RiskThreshold` deny reasons remain deferred per intent-plan.md V1 scope exclusions
