---
id: 001-sidecar-uds-bridge
unit: 003-egress-routing-and-dns-confinement
intent: 007-firma-run-sandbox-launcher
status: ready
priority: must
created: 2026-04-26T12:00:00Z
assigned_bolt: 016-egress-routing-and-dns-confinement
implemented: false
---

# Story: 001-sidecar-uds-bridge

## User Story

**As a** runtime operator
**I want** sandboxed agent traffic to exit through a local bridge bound to sidecar endpoint
**So that** mediation path is enforced structurally

## Acceptance Criteria

- [ ] **Given** sandbox starts, **When** bridge starts, **Then** it listens on sandbox-local loopback and forwards to sidecar UDS endpoint
- [ ] **Given** agent uses HTTP/HTTPS proxy settings, **When** outbound requests are made, **Then** they traverse bridge to sidecar
- [ ] **Given** bridge cannot connect sidecar endpoint, **When** request arrives, **Then** request fails with deterministic error and no external fallback path

## Technical Notes

- Bridge must support HTTP proxy and CONNECT-style forwarding behavior
- Sidecar endpoint path is per-run deterministic (`/run/firma-sidecar/<sandbox_id>.sock`-style)
- Keep bridge lightweight and observable

## Dependencies

### Requires
- 002-bwrap-backend-contract/002-bwrap-sandbox-launcher

### Enables
- 002-network-egress-lockdown
- 004-sidecar-unreachable-zero-egress

## Edge Cases

| Scenario | Expected Behavior |
|----------|-------------------|
| UDS socket file missing | Bridge startup fails, child launch blocked |
| Sidecar socket reconnect after transient outage | Bridge retries per policy without opening direct path |
| Multiple concurrent runs | Isolated bridge/socket paths per run |

## Out of Scope

- DNS resolver behavior
