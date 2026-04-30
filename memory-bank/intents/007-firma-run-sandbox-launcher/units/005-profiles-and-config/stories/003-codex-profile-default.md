---
id: 003-codex-profile-default
unit: 005-profiles-and-config
intent: 007-firma-run-sandbox-launcher
status: ready
priority: must
created: 2026-04-26T12:00:00Z
assigned_bolt: 019-profiles-and-config
implemented: false
---

# Story: 003-codex-profile-default

## User Story

**As a** Codex CLI user
**I want** a built-in codex profile with sane defaults
**So that** I can wrap Codex workflows without manual profile authoring

## Acceptance Criteria

- [ ] **Given** `--profile codex`, **When** runtime resolves config, **Then** codex-specific defaults are applied
- [ ] **Given** codex profile launch, **When** command runs, **Then** interactive behavior remains intact and required mounts/env passthrough are present
- [ ] **Given** codex profile uses default sidecar routing, **When** requests are made, **Then** mediation behavior matches generic security invariants

## Technical Notes

- Keep profile generic to FIR-61; Claude-specific behavior stays FIR-62
- Reuse same confinement primitives as generic profile
- Separate profile data from hardcoded branching where possible

## Dependencies

### Requires
- 001-config-schema-and-validation

### Enables
- 006-e2e-bench-and-docs/002-codex-profile-e2e

## Edge Cases

| Scenario | Expected Behavior |
|----------|-------------------|
| Codex binary absent in PATH | Launch fails with clear executable-not-found error |
| User overrides codex defaults | Override applied deterministically |
| Interactive terminal unavailable | Fallback mode with explicit warning |

## Out of Scope

- FIR-62 Claude profile behavior
