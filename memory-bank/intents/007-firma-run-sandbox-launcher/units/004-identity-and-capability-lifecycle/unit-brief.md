---
unit: 004-identity-and-capability-lifecycle
intent: 007-firma-run-sandbox-launcher
phase: inception
status: ready
created: 2026-04-26T12:00:00Z
updated: 2026-04-26T12:00:00Z
---

# Unit Brief: Identity and Capability Lifecycle

## Purpose

Define deterministic attribution model for sandboxed runs and prevent long-running agent failures from undefined capability renewal behavior.

## Scope

### In Scope
- Deterministic per-run identity model (`sandbox_id`, `session_id`, profile)
- Sidecar-bound identity propagation
- Renewable capability source and rotation behavior for persistent runtimes

### Out of Scope
- Sidecar policy semantics redesign
- Authority product-level workflow changes outside FIR-61 interfaces

---

## Assigned Requirements

| FR | Requirement | Priority |
|----|-------------|----------|
| FR-6 | Sidecar Routing Bridge and Identity Injection | Must |
| FR-9 | Long-Running Capability Lifecycle Contract | Must |

---

## Domain Concepts

### Key Entities
| Entity | Description | Attributes |
|--------|-------------|------------|
| RunIdentity | Deterministic identity for a wrapped run | sandbox_id, session_id, profile |
| AttributionHeaders | Transport identity projection | x-firma-* headers |
| CapabilityLease | Rotating capability material | token source, expiry, refresh window |

### Key Operations
| Operation | Description | Inputs | Outputs |
|-----------|-------------|--------|---------|
| build_identity | Generate run identity | profile + launch metadata | RunIdentity |
| inject_identity | Attach identity to mediated requests | RunIdentity + request | enriched request |
| refresh_capability | Rotate capability before expiry | current lease + provider | renewed lease |

---

## Story Summary

| Metric | Count |
|--------|-------|
| Total Stories | 3 |
| Must Have | 3 |
| Should Have | 0 |
| Could Have | 0 |

### Stories

| Story ID | Title | Priority | Status |
|----------|-------|----------|--------|
| 001-deterministic-sandbox-id | Deterministic run identity | Must | Planned |
| 002-attribution-header-injection | Sidecar attribution propagation | Must | Planned |
| 003-capability-rotation-contract | Long-running capability renewal | Must | Planned |

---

## Dependencies

### Depends On
| Unit | Reason |
|------|--------|
| 002-bwrap-backend-contract | Identity binds to sandbox lifecycle |

### Depended By
| Unit | Reason |
|------|--------|
| 006-e2e-bench-and-docs | E2E attribution and long-run scenarios depend on this unit |

---

## Constraints

- Identity must be deterministic and collision-safe for concurrent runs
- Capability renewal failures must result in explicit fail-closed behavior
- Renewal mechanism must support persistent agents without restart requirement

## Success Criteria

### Functional
- [ ] Every run has deterministic identity emitted in logs and requests
- [ ] Sidecar can attribute concurrent runs distinctly
- [ ] Capability rotation can occur without agent restart
- [ ] Expired/unrefreshable lease results in blocked egress with explicit reason

### Quality
- [ ] Long-running soak tests validate renewal behavior
- [ ] Identity propagation is covered by integration tests
