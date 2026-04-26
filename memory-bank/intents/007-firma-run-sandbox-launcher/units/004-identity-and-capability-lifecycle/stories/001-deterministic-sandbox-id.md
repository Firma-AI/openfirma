---
id: 001-deterministic-sandbox-id
unit: 004-identity-and-capability-lifecycle
intent: 007-firma-run-sandbox-launcher
status: ready
priority: must
created: 2026-04-26T12:00:00Z
assigned_bolt: 018-identity-and-capability-lifecycle
implemented: false
---

# Story: 001-deterministic-sandbox-id

## User Story

**As an** auditor
**I want** every `firma run` execution to have deterministic identity
**So that** concurrent runs can be attributed accurately

## Acceptance Criteria

- [ ] **Given** a new run starts, **When** identity is generated, **Then** `sandbox_id` and `session_id` are recorded deterministically for that run
- [ ] **Given** runtime components (bridge, DNS, sidecar path) initialize, **When** resources are created, **Then** resource names are derived from run identity
- [ ] **Given** run ends, **When** logs are reviewed, **Then** all lifecycle events include the run identity

## Technical Notes

- Prefer UUIDv7 or equivalent sortable id format
- Keep collision probability negligible under concurrent launches
- Include profile and command fingerprint metadata where safe

## Dependencies

### Requires
- 002-bwrap-backend-contract/002-bwrap-sandbox-launcher

### Enables
- 002-attribution-header-injection

## Edge Cases

| Scenario | Expected Behavior |
|----------|-------------------|
| Rapid concurrent launches | Unique identity per run |
| Partial startup failure | Identity still emitted in failure logs |
| Restart under same shell command | New run identity, same profile metadata |

## Out of Scope

- Capability token rotation logic
