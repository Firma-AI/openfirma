---
intent: 003-grpc-protocol-wire-contract
phase: inception
status: complete
created: 2026-03-27T09:00:00.000Z
updated: 2026-03-27T09:00:00.000Z
---

# Requirements: gRPC Protocol & Wire Contract

## Intent Overview

Define the Protobuf service definitions and shared message types that form the wire contract between `firma-sidecar` and `firma-authority`. This intent transforms `firma-proto` from a stub into the real gRPC contract with prost/tonic code generation. No runtime behavior — this is the protocol layer only.

## Business Goals

| Goal | Success Metric | Priority |
|------|----------------|----------|
| Single source of truth for wire contract | All inter-service types derived from `.proto` files, no hand-written duplicates | Must |
| AuthorityService RPC contract defined | `IssueCapability`, `WatchPolicyBundle`, `WatchRevocations` RPCs compilable | Must |
| Generated Rust code usable by downstream crates | `firma-sidecar` and `firma-authority` can import and use generated types | Must |
| Proto files document the security model | Comments capture Stage 1/Stage 2 distinction, permission perimeter, protocol unit semantics | Must |

---

## Functional Requirements

### FR-1: AuthorityService Proto Definition

- **Description**: Define `AuthorityService` gRPC service with three RPCs: `IssueCapability` (unary), `WatchPolicyBundle` (server-streaming), `WatchRevocations` (server-streaming)
- **Acceptance Criteria**: Service compiles via tonic-build; generated client/server traits available in `firma-proto`
- **Priority**: Must

### FR-2: ExecutionEnvelope Message

- **Description**: Define `ExecutionEnvelope` proto message as the core protocol unit of the Firma system. Contains intent (action, resource, params), capability token reference, metadata (session_id, agent_id, timestamp, trace_id, budget_consumed, risk_score), and provenance (reserved V1 placeholder)
- **Acceptance Criteria**: Message compiles; all fields match component reference section 4.2
- **Priority**: Must

### FR-3: CapabilityToken Message

- **Description**: Define `CapabilityToken` proto message with token_id, agent_id, action_set, resource_scope, issued_at, expiry, context_hash, format enum (PASETO_V4/JWT_RS256)
- **Acceptance Criteria**: Message compiles; fields match component reference section 5
- **Priority**: Must

### FR-4: RPC Request/Response Messages

- **Description**: Define request/response messages for all AuthorityService RPCs: `IssueCapabilityRequest`/`Response`, `WatchPolicyBundleRequest`/`PolicyBundleUpdate`, `WatchRevocationsRequest`/`RevocationEvent`
- **Acceptance Criteria**: All messages compile; fields match component reference sections 3.2–3.4
- **Priority**: Must

### FR-5: Supporting Messages

- **Description**: Define `PolicyBundle` (version, policies, entity_schema, ttl), `EnforcementDecision` enum (ALLOW, DENY, ABORT), `ConnectorResponse` (status_code, body, headers, latency, size)
- **Acceptance Criteria**: All messages compile and are re-exported from `firma-proto`
- **Priority**: Must

### FR-6: prost/tonic Build Pipeline

- **Description**: Add `build.rs` using `tonic_build` to compile `.proto` files into Rust code. Update `Cargo.toml` with prost, tonic, and tonic-build dependencies
- **Acceptance Criteria**: `cargo build -p firma-proto` generates code without errors; no manual type duplication
- **Priority**: Must

### FR-7: Workspace Integration

- **Description**: Ensure generated code integrates with existing workspace: passes clippy, fmt, and test checks. `lib.rs` re-exports generated types cleanly for downstream crates
- **Acceptance Criteria**: `cargo build --workspace`, `cargo clippy --workspace -- -D warnings`, `cargo fmt --check`, `cargo test --workspace` all pass
- **Priority**: Must

---

## Non-Functional Requirements

### Code Quality

| Requirement | Metric | Target |
|-------------|--------|--------|
| Generated code lint compliance | clippy warnings | 0 (with appropriate allows for generated code) |
| Proto documentation | All messages and RPCs documented | 100% |

---

## Constraints

### Technical Constraints

**Project-wide standards**: Coding standards, tech stack, and system architecture from `memory-bank/standards/` apply.

**Intent-specific constraints**:

- Proto files are the single source of truth — no hand-written Rust duplicates of proto messages
- Proto package: `firma.v1` (versioned namespace)
- No runtime dependencies beyond prost + tonic in `firma-proto`
- Generated code must work with workspace-level clippy configuration
- `firma-proto` should not depend on `firma-core` (the dependency goes the other way)

### Business Constraints

- Initial `ExecutionEnvelope` proto work should be preserved and integrated
- Security model documentation must be addressed in proto comments (Stage 1/2, permission perimeter, connector boundary rule)
- Connector code deferred to intent 006

---

## Assumptions

| Assumption | Risk if Invalid | Mitigation |
|------------|-----------------|------------|
| tonic-build works with workspace clippy config | Generated code may trigger pedantic lints | Use targeted `#[allow]` on generated code module |
| Proto package `firma.v1` is sufficient for V1 | Breaking changes require `firma.v2` | Design messages with optional/reserved fields for extensibility |
| `protoc` is available in CI environment | Build fails in CI | tonic-build bundles protoc via prost-build; verify in CI |
