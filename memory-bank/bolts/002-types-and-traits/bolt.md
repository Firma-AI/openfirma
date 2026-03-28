---
id: 002-types-and-traits
unit: 001-types-and-traits
intent: 002-core-types-shared-library
type: ddd-construction-bolt
status: in-progress
started: 2026-03-28T10:00:00Z
current_stage: adr-analysis
stories:
  - 001-capability-token-types
  - 002-execution-types
  - 003-decision-and-errors
  - 004-trait-interfaces
created: 2026-03-26T14:10:00Z
stages_completed:
  - name: domain-model
    completed: 2026-03-28T10:10:00Z
    artifact: ddd-01-domain-model.md
  - name: technical-design
    completed: 2026-03-28T10:20:00Z
    artifact: ddd-02-technical-design.md
requires_bolts:
  - 001-workspace-setup
enables_bolts:
  - 003-paseto-v4
requires_units: []
blocks: false
complexity:
  avg_complexity: 2
  avg_uncertainty: 1
  max_dependencies: 1
  testing_scope: 1
---

# Bolt: 002-types-and-traits

## Objective

Define all shared types, error types, and trait interfaces in `firma-core`. After this bolt, every downstream crate has a stable type foundation to build on.

## Stories Included

- [ ] **001-capability-token-types**: CapabilityClaims struct, TokenState enum (Must)
- [ ] **002-execution-types**: ExecutionEnvelope, ExecutionContext, sub-structs (Must)
- [ ] **003-decision-and-errors**: Decision enum, DenyReason, TokenError, EvaluationError (Must)
- [ ] **004-trait-interfaces**: PolicyEvaluator, TokenSigner, TokenVerifier, PolicyBundleStore, RevocationStore (Must)

## Bolt Type

**Type**: DDD Construction Bolt
**Definition**: `.specsmd/aidlc/templates/construction/bolt-types/ddd-construction-bolt.md`

## Stages

- [ ] **1. Domain Model**: Define all types, enums, error types, and trait signatures
- [ ] **2. Technical Design**: Module layout in firma-core/src/, public API surface, re-exports from lib.rs
- [ ] **3. Implementation**: Write all Rust code
- [ ] **4. Test**: Unit tests for construction, Display, Serialize, trait object safety
- [ ] **5. Review**: Verify all FRs met, Clippy clean, no unsafe

## Expected Outputs

- `firma-core/src/token.rs` — CapabilityClaims, TokenState
- `firma-core/src/envelope.rs` — ExecutionEnvelope, Intent, RequestMetadata, ExecutionContext
- `firma-core/src/decision.rs` — Decision, DenyReason
- `firma-core/src/error.rs` — TokenError, EvaluationError
- `firma-core/src/traits.rs` — All trait definitions
- `firma-core/src/lib.rs` — Module declarations and public re-exports
- Updated `firma-core/Cargo.toml` with serde, thiserror, chrono dependencies

## Dependencies

### Bolt Dependencies (within intent)

- **001-workspace-setup** (Required): Workspace scaffolding must exist — Complete

### Unit Dependencies (cross-unit)

- None

### Enables (other bolts waiting on this)

- 003-paseto-v4

## Success Criteria

- [ ] `cargo build --workspace` succeeds
- [ ] `cargo clippy --workspace -- -D warnings` passes
- [ ] All types are publicly exported from `firma-core`
- [ ] All traits are object-safe (tested)
- [ ] Unit tests pass

## Notes

All 4 stories are in one bolt because the types cross-reference each other heavily. Building them incrementally would cause compilation errors at every intermediate step.
