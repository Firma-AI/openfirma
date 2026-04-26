---
id: 003-dns-stub-and-resolver-wiring
unit: 003-egress-routing-and-dns-confinement
intent: 007-firma-run-sandbox-launcher
status: ready
priority: must
created: 2026-04-26T12:00:00Z
assigned_bolt: 017-egress-routing-and-dns-confinement
implemented: false
---

# Story: 003-dns-stub-and-resolver-wiring

## User Story

**As a** security reviewer
**I want** explicit DNS confinement behavior in sandbox
**So that** host resolver bypass is structurally impossible

## Acceptance Criteria

- [ ] **Given** sandbox is prepared, **When** `resolv.conf` is provisioned, **Then** it points to sandbox-local DNS stub (not host resolver)
- [ ] **Given** DNS query is issued in sandbox, **When** resolver path is used, **Then** query traverses Firma-controlled forwarding path
- [ ] **Given** query attempts direct external resolver path, **When** confinement applies, **Then** query is blocked or redirected to controlled stub

## Technical Notes

- Generate per-run resolver file and mount it into sandbox
- DNS stub forwards over controlled channel tied to sidecar path
- Fail closed when DNS stub upstream unavailable

## Dependencies

### Requires
- 002-network-egress-lockdown

### Enables
- 006-e2e-bench-and-docs/001-generic-profile-e2e

## Edge Cases

| Scenario | Expected Behavior |
|----------|-------------------|
| Agent runs `dig @8.8.8.8` | Query does not bypass controlled path |
| DNS stub process crashes | Name resolution fails closed |
| Application performs local resolver retries | Retries stay within controlled path |

## Out of Scope

- Sidecar policy decisions over domain allowlists
