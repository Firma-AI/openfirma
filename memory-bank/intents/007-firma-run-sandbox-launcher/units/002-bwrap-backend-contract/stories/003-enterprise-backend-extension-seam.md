---
id: 003-enterprise-backend-extension-seam
unit: 002-bwrap-backend-contract
intent: 007-firma-run-sandbox-launcher
status: ready
priority: must
created: 2026-04-26T12:00:00Z
assigned_bolt: 015-bwrap-backend-contract
implemented: false
---

# Story: 003-enterprise-backend-extension-seam

## User Story

**As a** platform maintainer
**I want** a clean extension seam for enterprise sandbox profiles
**So that** Firecracker-style add-ons are additive, not rewrites

## Acceptance Criteria

- [ ] **Given** backend registry exists, **When** enterprise profile is configured, **Then** runtime resolves backend via registry rather than hardcoded branching
- [ ] **Given** enterprise backend is unavailable in FIR-61 build, **When** requested, **Then** wrapper returns explicit not-implemented guidance
- [ ] **Given** backend-neutral orchestration path, **When** new backend is added later, **Then** CLI/user surface remains stable

## Technical Notes

- Keep profile-to-backend mapping explicit in config
- Avoid Linux-specific assumptions in orchestration layer
- Document extension points in code comments and docs

## Dependencies

### Requires
- 001-backend-trait-and-proof-objects

### Enables
- FIR-60 matrix completion post-FIR-61

## Edge Cases

| Scenario | Expected Behavior |
|----------|-------------------|
| Enterprise profile selected on unsupported host | Clear unsupported message |
| Backend plugin registration conflict | Fail-fast with deterministic error |
| Missing backend config fields | Schema validation error |

## Out of Scope

- Firecracker runtime implementation
