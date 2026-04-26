---
id: 001-backend-trait-and-proof-objects
unit: 002-bwrap-backend-contract
intent: 007-firma-run-sandbox-launcher
status: ready
priority: must
created: 2026-04-26T12:00:00Z
assigned_bolt: 015-bwrap-backend-contract
implemented: false
---

# Story: 001-backend-trait-and-proof-objects

## User Story

**As a** maintainer
**I want** a stable backend interface and proof objects
**So that** FIR-61 can ship Linux now without boxing out future backends

## Acceptance Criteria

- [ ] **Given** backend trait is defined, **When** runtime compiles, **Then** orchestration is backend-agnostic
- [ ] **Given** backend setup succeeds, **When** proof object is returned, **Then** it contains verifiable confinement/routing metadata
- [ ] **Given** backend is unsupported on host OS, **When** selected, **Then** wrapper exits with explicit unsupported error

## Technical Notes

- Keep trait minimal and aligned with FIR-60 contract terms
- Use typed handles for lifecycle boundaries
- Keep proof object serializable for diagnostics

## Dependencies

### Requires
- 001-cli-runtime-orchestrator/004-fail-closed-startup-order

### Enables
- 002-bwrap-sandbox-launcher
- 003-enterprise-backend-extension-seam

## Edge Cases

| Scenario | Expected Behavior |
|----------|-------------------|
| Backend partial implementation | Compile-time contract catches missing methods |
| Unknown backend profile | Explicit configuration error |
| Proof data unavailable | Backend startup treated as failure |

## Out of Scope

- Concrete network rules
