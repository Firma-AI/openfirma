---
id: 001-generic-profile-e2e
unit: 006-e2e-bench-and-docs
intent: 007-firma-run-sandbox-launcher
status: ready
priority: must
created: 2026-04-26T12:00:00Z
assigned_bolt: 020-e2e-bench-and-docs
implemented: false
---

# Story: 001-generic-profile-e2e

## User Story

**As a** release owner
**I want** end-to-end evidence for generic profile mediation and fail-closed behavior
**So that** FIR-61 acceptance is objectively verifiable

## Acceptance Criteria

- [ ] **Given** generic profile launch, **When** agent makes outbound HTTP request, **Then** sidecar observes and audits the request
- [ ] **Given** shell tool (`curl`/`wget`) is executed in sandbox, **When** request runs, **Then** request is mediated or blocked (never direct)
- [ ] **Given** sidecar denies request by policy, **When** agent receives outcome, **Then** error is surfaced as structured tool/runtime error
- [ ] **Given** sidecar is unavailable, **When** request is attempted, **Then** no external egress succeeds

## Technical Notes

- Use deterministic test fixtures and local mock upstreams
- Include explicit bypass-attempt probes
- Capture audit evidence in test artifacts

## Dependencies

### Requires
- 003-egress-routing-and-dns-confinement
- 004-identity-and-capability-lifecycle
- 005-profiles-and-config/002-generic-profile-default

### Enables
- FIR-61 acceptance sign-off

## Edge Cases

| Scenario | Expected Behavior |
|----------|-------------------|
| Sidecar deny payload format changes | Test validates stable contract |
| Upstream timeout | Distinct abort path assertion |
| Capability renewal in long-run test | Behavior remains deterministic |

## Out of Scope

- Codex-specific behavior
