---
id: 002-network-egress-lockdown
unit: 003-egress-routing-and-dns-confinement
intent: 007-firma-run-sandbox-launcher
status: ready
priority: must
created: 2026-04-26T12:00:00Z
assigned_bolt: 016-egress-routing-and-dns-confinement
implemented: false
---

# Story: 002-network-egress-lockdown

## User Story

**As a** security engineer
**I want** direct outbound egress from sandbox blocked
**So that** ignoring proxy configuration cannot bypass sidecar

## Acceptance Criteria

- [ ] **Given** sandboxed process attempts direct external TCP connect, **When** no mediation path is used, **Then** connect attempt fails
- [ ] **Given** mediation bridge is healthy, **When** outbound HTTP traffic is sent through proxy path, **Then** request succeeds via sidecar
- [ ] **Given** sidecar path is down, **When** outbound traffic is attempted, **Then** no external fallback path exists

## Technical Notes

- Enforce via backend network namespace confinement semantics
- Document explicit invariants in `EnforcementProof`
- Include negative-path tests (direct IP, direct hostname)

## Dependencies

### Requires
- 001-sidecar-uds-bridge

### Enables
- 004-sidecar-unreachable-zero-egress

## Edge Cases

| Scenario | Expected Behavior |
|----------|-------------------|
| Agent unsets `HTTP_PROXY` | External calls still fail |
| Agent uses custom raw socket client | External path blocked |
| Agent spawns subprocess with clean env | External path still blocked |

## Out of Scope

- Capability token handling
