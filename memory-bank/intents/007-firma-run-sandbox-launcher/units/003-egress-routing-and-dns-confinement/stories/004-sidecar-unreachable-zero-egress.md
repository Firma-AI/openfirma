---
id: 004-sidecar-unreachable-zero-egress
unit: 003-egress-routing-and-dns-confinement
intent: 007-firma-run-sandbox-launcher
status: ready
priority: must
created: 2026-04-26T12:00:00Z
assigned_bolt: 017-egress-routing-and-dns-confinement
implemented: false
---

# Story: 004-sidecar-unreachable-zero-egress

## User Story

**As a** platform operator
**I want** sidecar outages to cause deterministic fail-closed behavior
**So that** runtime never falls back to direct external access

## Acceptance Criteria

- [ ] **Given** sidecar is unreachable at startup, **When** `firma run` starts, **Then** wrapped agent launch is blocked
- [ ] **Given** sidecar becomes unreachable mid-session, **When** outbound request is attempted, **Then** request fails with explicit sidecar-unavailable reason
- [ ] **Given** outage occurs, **When** verification runs, **Then** no external egress succeeds from sandbox

## Technical Notes

- Cover startup and runtime outage scenarios
- Emit machine-parseable error code for automation
- Reuse same invariant checks used in benchmark harness

## Dependencies

### Requires
- 001-sidecar-uds-bridge
- 002-network-egress-lockdown

### Enables
- 006-e2e-bench-and-docs/001-generic-profile-e2e
- 006-e2e-bench-and-docs/002-codex-profile-e2e

## Edge Cases

| Scenario | Expected Behavior |
|----------|-------------------|
| Sidecar flaps quickly | No successful direct egress between failures |
| Bridge backlog accumulates | Requests fail cleanly without panic |
| Sidecar recovers | Traffic resumes through mediated path only |

## Out of Scope

- Policy decision semantics
