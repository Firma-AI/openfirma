---
id: 001-config-schema-and-validation
unit: 005-profiles-and-config
intent: 007-firma-run-sandbox-launcher
status: ready
priority: must
created: 2026-04-26T12:00:00Z
assigned_bolt: 019-profiles-and-config
implemented: false
---

# Story: 001-config-schema-and-validation

## User Story

**As a** user
**I want** a validated config schema for `firma-run`
**So that** misconfiguration is caught before runtime launch

## Acceptance Criteria

- [ ] **Given** valid config file, **When** parser runs, **Then** runtime receives typed config object
- [ ] **Given** unknown/invalid fields, **When** parser validates, **Then** startup fails with field-specific errors
- [ ] **Given** profile defaults and overrides, **When** config resolves, **Then** effective config is deterministic

## Technical Notes

- Use serde + explicit validation methods
- Keep schema versioning ready for future extensions
- Provide `--print-effective-config` debug output

## Dependencies

### Requires
- 001-cli-runtime-orchestrator/001-cli-surface-and-arg-parsing

### Enables
- 002-generic-profile-default
- 003-codex-profile-default

## Edge Cases

| Scenario | Expected Behavior |
|----------|-------------------|
| Empty config file | Defaults resolve successfully |
| Invalid domain pattern | Validation error with path |
| Duplicate profile keys | Deterministic precedence or fail with clear error |

## Out of Scope

- Runtime backend behavior
