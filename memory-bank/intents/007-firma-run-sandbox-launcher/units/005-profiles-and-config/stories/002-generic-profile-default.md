---
id: 002-generic-profile-default
unit: 005-profiles-and-config
intent: 007-firma-run-sandbox-launcher
status: ready
priority: must
created: 2026-04-26T12:00:00Z
assigned_bolt: 019-profiles-and-config
implemented: false
---

# Story: 002-generic-profile-default

## User Story

**As a** first-time user
**I want** a default generic profile that works for Python/Node agents
**So that** I can run quickly without custom tuning

## Acceptance Criteria

- [ ] **Given** no profile flag provided, **When** command runs, **Then** `generic` profile is selected
- [ ] **Given** a basic Python or Node agent command, **When** wrapped by generic profile, **Then** command launches with required baseline mounts/env rules
- [ ] **Given** profile defaults are applied, **When** resolved config is inspected, **Then** sidecar endpoint and confinement knobs are present

## Technical Notes

- Keep defaults minimal and conservative
- Include required runtime env passthrough only
- Document profile behavior in README

## Dependencies

### Requires
- 001-config-schema-and-validation

### Enables
- 006-e2e-bench-and-docs/001-generic-profile-e2e

## Edge Cases

| Scenario | Expected Behavior |
|----------|-------------------|
| User overrides mount list | Merge respects explicit override policy |
| Missing optional env variables | Launch still succeeds with warnings where appropriate |
| Non-Python/Node command | Still runs unless disallowed by policy |

## Out of Scope

- Codex-specific defaults
