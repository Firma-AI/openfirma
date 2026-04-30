---
id: 003-capability-rotation-contract
unit: 004-identity-and-capability-lifecycle
intent: 007-firma-run-sandbox-launcher
status: ready
priority: must
created: 2026-04-26T12:00:00Z
assigned_bolt: 018-identity-and-capability-lifecycle
implemented: false
---

# Story: 003-capability-rotation-contract

## User Story

**As an** operator running long-lived agents
**I want** capability material to rotate without restarting processes
**So that** persistent agents do not fail when short-lived tokens expire

## Acceptance Criteria

- [ ] **Given** run is configured for rotating capability mode, **When** current capability approaches expiry, **Then** wrapper loads replacement capability before expiry threshold
- [ ] **Given** capability source fails during renewal, **When** grace window passes, **Then** outbound traffic fails closed with explicit renewal error
- [ ] **Given** renewal succeeds, **When** subsequent requests are made, **Then** traffic continues without agent restart

## Technical Notes

- Support provider contract: file path, command hook, or plugin source
- Keep overlap window to avoid race between old/new token validity
- Emit renewal lifecycle events for observability

## Dependencies

### Requires
- 001-deterministic-sandbox-id
- 002-attribution-header-injection

### Enables
- 006-e2e-bench-and-docs/001-generic-profile-e2e (long-run variant)

## Edge Cases

| Scenario | Expected Behavior |
|----------|-------------------|
| Token expires before replacement available | Requests denied fail-closed |
| Replacement token malformed | Reject replacement, keep old until expiry threshold |
| Renewal source flaps | Backoff and deterministic error state transitions |

## Out of Scope

- Authority issuance workflow redesign
