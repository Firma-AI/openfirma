---
id: 004-fail-closed-startup-order
unit: 001-cli-runtime-orchestrator
intent: 007-firma-run-sandbox-launcher
status: ready
priority: must
created: 2026-04-26T12:00:00Z
assigned_bolt: 014-cli-runtime-orchestrator
implemented: false
---

# Story: 004-fail-closed-startup-order

## User Story

**As a** security-conscious operator
**I want** wrapped process launch to be gated on confinement readiness
**So that** no request escapes before enforcement path is active

## Acceptance Criteria

- [ ] **Given** backend is not ready, **When** `firma run` starts, **Then** wrapped process is not launched
- [ ] **Given** sidecar bridge fails startup, **When** runtime initializes, **Then** wrapper exits with fail-closed error
- [ ] **Given** all prerequisites pass, **When** startup completes, **Then** wrapped process starts exactly once

## Technical Notes

- Define startup graph: config -> backend -> bridge -> DNS -> child
- Emit clear reason-coded errors
- Treat partial startup as failure requiring cleanup

## Dependencies

### Requires
- 001-cli-surface-and-arg-parsing
- 002-process-supervision-and-signal-forwarding

### Enables
- 003-egress-routing-and-dns-confinement stories

## Edge Cases

| Scenario | Expected Behavior |
|----------|-------------------|
| Sidecar starts then immediately fails health | Child launch blocked |
| Cleanup fails after partial startup | Best-effort cleanup + explicit warning |
| Duplicate startup trigger | Idempotent guard prevents double launch |

## Out of Scope

- Capability rotation semantics
