---
id: 004-readme-and-ops-guide
unit: 006-e2e-bench-and-docs
intent: 007-firma-run-sandbox-launcher
status: ready
priority: must
created: 2026-04-26T12:00:00Z
assigned_bolt: 020-e2e-bench-and-docs
implemented: false
---

# Story: 004-readme-and-ops-guide

## User Story

**As a** new adopter
**I want** clear documentation for `firma run`
**So that** I can use FIR-61 safely without reading internal design docs

## Acceptance Criteria

- [ ] **Given** README updates, **When** user follows quickstart, **Then** they can launch generic profile successfully
- [ ] **Given** docs describe scope, **When** user reads FIR-61 section, **Then** Linux-only scope and FIR-62 separation are explicit
- [ ] **Given** fail-closed semantics, **When** sidecar is unavailable, **Then** expected behavior and troubleshooting steps are documented
- [ ] **Given** benchmark artifacts exist, **When** docs are updated, **Then** key measured numbers and how to reproduce are included

## Technical Notes

- Keep examples copy-pastable
- Reference profile defaults and config schema
- Include security limitations/non-goals explicitly

## Dependencies

### Requires
- 003-benchmark-harness-and-json-artifacts

### Enables
- Launch readiness communication

## Edge Cases

| Scenario | Expected Behavior |
|----------|-------------------|
| User on unsupported OS | Docs direct to current limitations clearly |
| Missing `bwrap` dependency | Troubleshooting includes install/preflight guidance |
| Outdated benchmark numbers | Docs note measurement date and hardware context |

## Out of Scope

- Product marketing collateral outside repo docs
