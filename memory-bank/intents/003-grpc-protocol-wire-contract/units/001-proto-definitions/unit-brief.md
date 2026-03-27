---
unit: 001-proto-definitions
intent: 003-grpc-protocol-wire-contract
phase: inception
status: planned
unit_type: backend
default_bolt_type: simple-construction-bolt
created: 2026-03-27T09:00:00.000Z
updated: 2026-03-27T09:00:00.000Z
---

# Unit Brief: Proto Definitions

## Purpose

Define the Protobuf service and message types that form the Firma wire contract, set up the prost/tonic build pipeline, and integrate generated code into the workspace. Extends initial `ExecutionEnvelope` proto work with AuthorityService RPCs and security model documentation.

## Scope

### In Scope

- `.proto` files defining AuthorityService and all shared message types
- `build.rs` with tonic-build compilation
- `Cargo.toml` dependency updates (prost, tonic, tonic-build)
- `lib.rs` re-exports of generated code
- Proto-level documentation capturing security model invariants

### Out of Scope

- Server implementation of AuthorityService (intent 005)
- Client usage from firma-sidecar (intent 006)
- Connector trait and registry (intent 006)
- Capability token signing/validation logic (intent 002)
- Cedar policy types (intent 002)

---

## Assigned Requirements

| FR | Requirement | Priority |
|----|-------------|----------|
| FR-1 | AuthorityService Proto Definition | Must |
| FR-2 | ExecutionEnvelope Message | Must |
| FR-3 | CapabilityToken Message | Must |
| FR-4 | RPC Request/Response Messages | Must |
| FR-5 | Supporting Messages | Must |
| FR-6 | prost/tonic Build Pipeline | Must |
| FR-7 | Workspace Integration | Must |

---

## Domain Concepts

### Key Entities

| Entity | Description | Attributes |
|--------|-------------|------------|
| AuthorityService | gRPC service contract between sidecar and authority | 3 RPCs |
| ExecutionEnvelope | Core protocol unit flowing through the entire system | intent, capability, metadata, provenance |
| CapabilityToken | Signed permission token issued by authority | token_id, agent_id, actions, scope, expiry, format |
| PolicyBundle | Cedar policy set distributed to sidecars | version, policies, schema, ttl |
| RevocationEvent | Token invalidation signal | token_id, reason, timestamp |

### Key Operations

| Operation | Description | Inputs | Outputs |
|-----------|-------------|--------|---------|
| IssueCapability | Authority issues a capability token | Agent identity, requested actions, scope | Signed capability token or denial |
| WatchPolicyBundle | Authority streams policy updates | Subscription request | Stream of policy bundle updates |
| WatchRevocations | Authority streams revocation events | Subscription request | Stream of revocation events |

---

## Story Summary

| Metric | Count |
|--------|-------|
| Total Stories | 4 |
| Must Have | 4 |
| Should Have | 0 |
| Could Have | 0 |

### Stories

| Story ID | Title | Priority | Status |
|----------|-------|----------|--------|
| 001-authority-service-proto | AuthorityService RPC definitions | Must | Planned |
| 002-execution-envelope-proto | ExecutionEnvelope and shared messages | Must | Planned |
| 003-build-pipeline | prost/tonic build pipeline | Must | Planned |
| 004-workspace-integration | Workspace integration and CI validation | Must | Planned |

---

## Dependencies

### Depends On

| Unit | Reason |
|------|--------|
| Intent 001 / 001-workspace-setup | Workspace structure, CI, Makefile |

### Depended By

| Unit | Reason |
|------|--------|
| Intent 004 (example agents) | Needs proto types for test harness |
| Intent 005 (mini authority) | Implements AuthorityService server |
| Intent 006 (sidecar proxy) | Uses AuthorityService client, ExecutionEnvelope |

### External Dependencies

| System | Purpose | Risk |
|--------|---------|------|
| prost / tonic | Proto code generation | Low — mature crates |
| protobuf compiler | Proto compilation | Low — bundled by prost-build |

---

## Constraints

- Proto files are single source of truth — no hand-written duplicates
- Proto package: `firma.v1`
- `firma-proto` must not depend on `firma-core`
- Generated code must pass workspace clippy/fmt checks

---

## Success Criteria

### Functional

- [ ] `cargo build -p firma-proto` generates code from proto files
- [ ] `cargo build --workspace` succeeds
- [ ] `cargo clippy --workspace -- -D warnings` passes
- [ ] `cargo fmt --check` passes
- [ ] `cargo test --workspace` passes
- [ ] Generated `AuthorityServiceClient` and `AuthorityServiceServer` traits available
- [ ] `ExecutionEnvelope`, `CapabilityToken`, `PolicyBundle` types importable

### Quality

- [ ] All proto messages and RPCs have doc comments
- [ ] Security model invariants documented in proto comments (Stage 1/2, permission perimeter)
