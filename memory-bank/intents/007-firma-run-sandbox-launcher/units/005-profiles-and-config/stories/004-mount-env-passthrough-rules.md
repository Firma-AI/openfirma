---
id: 004-mount-env-passthrough-rules
unit: 005-profiles-and-config
intent: 007-firma-run-sandbox-launcher
status: ready
priority: must
created: 2026-04-26T12:00:00Z
assigned_bolt: 019-profiles-and-config
implemented: false
---

# Story: 004-mount-env-passthrough-rules

## User Story

**As a** platform maintainer
**I want** explicit mount/env passthrough policy rules
**So that** runtime access surface is intentional and reviewable

## Acceptance Criteria

- [ ] **Given** profile defines mount allowlist, **When** sandbox launches, **Then** only allowed paths are mounted
- [ ] **Given** env passthrough rules exist, **When** runtime starts, **Then** only allowed variables are inherited
- [ ] **Given** denied path/env is requested, **When** validation runs, **Then** startup fails with clear policy violation message

## Technical Notes

- Support explicit allow/deny precedence
- Keep secrets out of default passthrough unless explicitly configured
- Emit effective mount/env set in debug logs

## Dependencies

### Requires
- 001-config-schema-and-validation

### Enables
- 006-e2e-bench-and-docs stories

## Edge Cases

| Scenario | Expected Behavior |
|----------|-------------------|
| Relative mount path in config | Validation error |
| Duplicate env rule entries | Deterministic resolution |
| Sensitive env accidentally allowed | Warning/guardrail in validation |

## Out of Scope

- Policy enforcement decisions in sidecar
