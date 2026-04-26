---
id: 002-codex-profile-e2e
unit: 006-e2e-bench-and-docs
intent: 007-firma-run-sandbox-launcher
status: ready
priority: must
created: 2026-04-26T12:00:00Z
assigned_bolt: 020-e2e-bench-and-docs
implemented: false
---

# Story: 002-codex-profile-e2e

## User Story

**As a** release owner
**I want** codex profile verified end-to-end under the same security invariants
**So that** profile-specific UX does not introduce bypass behavior

## Acceptance Criteria

- [ ] **Given** `--profile codex`, **When** codex command runs through wrapper, **Then** interactive behavior remains usable
- [ ] **Given** codex-triggered outbound HTTP activity, **When** requests are made, **Then** sidecar observes/audits requests
- [ ] **Given** sidecar deny or outage, **When** codex request fails, **Then** codex-visible errors are structured and deterministic

## Technical Notes

- Reuse generic E2E harness with codex profile matrix entries
- Validate TTY behavior explicitly
- Capture logs/artifacts for launch demos

## Dependencies

### Requires
- 001-cli-runtime-orchestrator/003-tui-safe-stdio-passthrough
- 003-egress-routing-and-dns-confinement
- 005-profiles-and-config/003-codex-profile-default

### Enables
- FIR-61 acceptance sign-off

## Edge Cases

| Scenario | Expected Behavior |
|----------|-------------------|
| Codex command exits non-zero | Wrapper propagates status correctly |
| Terminal resize during run | No corruption of interactive output |
| Concurrent codex runs | Distinct attribution in sidecar logs |

## Out of Scope

- FIR-62 Claude integration
