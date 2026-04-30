---
intent: 007-firma-run-sandbox-launcher
phase: inception
status: units-decomposed
updated: 2026-04-26T12:00:00Z
---

# Firma Run Sandbox Launcher - Unit Decomposition

## Units Overview

This intent decomposes into 6 units of work:

### Unit 1: 001-cli-runtime-orchestrator

**Description**: CLI surface, command parsing, lifecycle management, signal handling, and interactive-safe stdio passthrough.

**Assigned Requirements**: FR-1, FR-2

**Stories**:
- 001-cli-surface-and-arg-parsing
- 002-process-supervision-and-signal-forwarding
- 003-tui-safe-stdio-passthrough
- 004-fail-closed-startup-order

**Deliverables**:
- `firma run` command entrypoint
- supervisor lifecycle model
- signal + exit-code propagation contract

**Dependencies**:
- Depends on: None (foundational runtime shell)
- Depended by: all units

**Estimated Complexity**: M

---

### Unit 2: 002-bwrap-backend-contract

**Description**: Backend interface + Linux `bwrap` implementation skeleton + explicit enterprise profile extension seam.

**Assigned Requirements**: FR-3

**Stories**:
- 001-backend-trait-and-proof-objects
- 002-bwrap-sandbox-launcher
- 003-enterprise-backend-extension-seam

**Deliverables**:
- backend trait and capability checks
- bwrap prepare/start/teardown primitives
- unsupported backend diagnostics for non-Linux FIR-61 scope

**Dependencies**:
- Depends on: 001-cli-runtime-orchestrator
- Depended by: 003-egress-routing-and-dns-confinement, 004-identity-and-capability-lifecycle

**Estimated Complexity**: M

---

### Unit 3: 003-egress-routing-and-dns-confinement

**Description**: Structural sidecar routing bridge, no-bypass network confinement, explicit DNS path confinement.

**Assigned Requirements**: FR-4, FR-5

**Stories**:
- 001-sidecar-uds-bridge
- 002-network-egress-lockdown
- 003-dns-stub-and-resolver-wiring
- 004-sidecar-unreachable-zero-egress

**Deliverables**:
- sandbox-local proxy bridge to sidecar endpoint
- egress lockdown invariants
- DNS stub + generated resolv.conf strategy
- fail-closed outage behavior

**Dependencies**:
- Depends on: 002-bwrap-backend-contract
- Depended by: 006-e2e-bench-and-docs

**Estimated Complexity**: XL

---

### Unit 4: 004-identity-and-capability-lifecycle

**Description**: Deterministic sandbox identity injection and long-running capability renewal semantics.

**Assigned Requirements**: FR-6, FR-9

**Stories**:
- 001-deterministic-sandbox-id
- 002-attribution-header-injection
- 003-capability-rotation-contract

**Deliverables**:
- run identity model (`sandbox_id`, `session_id`, profile)
- sidecar-attribution headers/claims path
- renewable capability source contract for persistent agents

**Dependencies**:
- Depends on: 002-bwrap-backend-contract
- Depended by: 006-e2e-bench-and-docs

**Estimated Complexity**: L

---

### Unit 5: 005-profiles-and-config

**Description**: Config schema, profile merge logic, built-in `generic` and `codex` defaults, mount/env passthrough policies.

**Assigned Requirements**: FR-7, FR-8

**Stories**:
- 001-config-schema-and-validation
- 002-generic-profile-default
- 003-codex-profile-default
- 004-mount-env-passthrough-rules

**Deliverables**:
- config file format + validation
- built-in day-one profiles
- effective config generation for debug

**Dependencies**:
- Depends on: 001-cli-runtime-orchestrator
- Depended by: 006-e2e-bench-and-docs

**Estimated Complexity**: M

---

### Unit 6: 006-e2e-bench-and-docs

**Description**: End-to-end verification, benchmark harness, and user/operator documentation for launch readiness.

**Assigned Requirements**: FR-10, FR-11, FR-12

**Stories**:
- 001-generic-profile-e2e
- 002-codex-profile-e2e
- 003-benchmark-harness-and-json-artifacts
- 004-readme-and-ops-guide

**Deliverables**:
- E2E suites for both profiles
- benchmark tooling + output artifacts
- README/docs updates for FIR-61 positioning

**Dependencies**:
- Depends on: 003-egress-routing-and-dns-confinement, 004-identity-and-capability-lifecycle, 005-profiles-and-config
- Depended by: None

**Estimated Complexity**: L

---

## Requirement-to-Unit Mapping

- **FR-1, FR-2** -> `001-cli-runtime-orchestrator`
- **FR-3** -> `002-bwrap-backend-contract`
- **FR-4, FR-5** -> `003-egress-routing-and-dns-confinement`
- **FR-6, FR-9** -> `004-identity-and-capability-lifecycle`
- **FR-7, FR-8** -> `005-profiles-and-config`
- **FR-10, FR-11, FR-12** -> `006-e2e-bench-and-docs`

## Unit Dependency Graph

```text
001-cli-runtime-orchestrator ─┬─> 002-bwrap-backend-contract ─┬─> 003-egress-routing-and-dns-confinement ─┐
                               │                               └─> 004-identity-and-capability-lifecycle ───┤
                               └─> 005-profiles-and-config ───────────────────────────────────────────────────┤
                                                                                                               ▼
                                                                                              006-e2e-bench-and-docs
```

## Execution Order

1. Phase 1: `001-cli-runtime-orchestrator`
2. Phase 2 (parallel): `002-bwrap-backend-contract`, `005-profiles-and-config`
3. Phase 3 (parallel): `003-egress-routing-and-dns-confinement`, `004-identity-and-capability-lifecycle`
4. Phase 4: `006-e2e-bench-and-docs`
