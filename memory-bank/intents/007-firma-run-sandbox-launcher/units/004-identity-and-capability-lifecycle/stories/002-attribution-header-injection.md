---
id: 002-attribution-header-injection
unit: 004-identity-and-capability-lifecycle
intent: 007-firma-run-sandbox-launcher
status: ready
priority: must
created: 2026-04-26T12:00:00Z
assigned_bolt: 018-identity-and-capability-lifecycle
implemented: false
---

# Story: 002-attribution-header-injection

## User Story

**As a** policy operator
**I want** mediated requests to carry wrapper identity claims
**So that** sidecar policy and audit can distinguish runs

## Acceptance Criteria

- [ ] **Given** request leaves sandbox via bridge, **When** request is forwarded, **Then** identity headers/claims include `sandbox_id`, `session_id`, and `profile`
- [ ] **Given** multiple concurrent `firma-run` instances, **When** sidecar logs are inspected, **Then** events are separable by run identity
- [ ] **Given** identity injection fails, **When** forwarding is attempted, **Then** request fails closed rather than sending unattributed traffic

## Technical Notes

- Reuse existing `x-firma-session-id` semantics where possible
- Keep header names and casing stable/documented
- Ensure sensitive values are not leaked in user-facing errors

## Dependencies

### Requires
- 001-deterministic-sandbox-id

### Enables
- 006-e2e-bench-and-docs/001-generic-profile-e2e
- 006-e2e-bench-and-docs/002-codex-profile-e2e

## Edge Cases

| Scenario | Expected Behavior |
|----------|-------------------|
| Upstream strips unknown headers | Audit still retains attribution from sidecar entry point |
| Header collisions with user headers | Wrapper-prefixed headers take precedence |
| Retries occur | Identity remains stable for run |

## Out of Scope

- Cedar policy authoring for identity attributes
