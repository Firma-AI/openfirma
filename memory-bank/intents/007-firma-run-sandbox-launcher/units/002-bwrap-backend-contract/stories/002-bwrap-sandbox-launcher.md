---
id: 002-bwrap-sandbox-launcher
unit: 002-bwrap-backend-contract
intent: 007-firma-run-sandbox-launcher
status: ready
priority: must
created: 2026-04-26T12:00:00Z
assigned_bolt: 015-bwrap-backend-contract
implemented: false
---

# Story: 002-bwrap-sandbox-launcher

## User Story

**As an** FIR-61 user on Linux
**I want** `firma-run` to launch my command in bubblewrap
**So that** execution boundary is enforced structurally

## Acceptance Criteria

- [ ] **Given** host supports required namespace features, **When** command launches, **Then** process runs under bwrap isolation
- [ ] **Given** required tooling is missing, **When** launch is attempted, **Then** startup fails with actionable prerequisite diagnostics
- [ ] **Given** wrapper exits, **When** teardown runs, **Then** sandbox resources are cleaned up

## Technical Notes

- Validate `bwrap` availability in preflight
- Use dedicated mount plan per profile
- Keep command argv and cwd mapping deterministic

## Dependencies

### Requires
- 001-backend-trait-and-proof-objects

### Enables
- Unit 003 egress confinement work
- Unit 004 identity lifecycle integration

## Edge Cases

| Scenario | Expected Behavior |
|----------|-------------------|
| Invalid mount path configured | Launch fails before child start |
| bwrap exits immediately | Wrapper surfaces backend failure |
| Sandbox child forks grandchildren | Teardown still reaps managed process tree |

## Out of Scope

- DNS and sidecar routing behavior
