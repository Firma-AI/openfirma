---
unit: 003-egress-routing-and-dns-confinement
intent: 007-firma-run-sandbox-launcher
phase: inception
status: ready
created: 2026-04-26T12:00:00Z
updated: 2026-04-26T12:00:00Z
---

# Unit Brief: Egress Routing and DNS Confinement

## Purpose

Guarantee structural mediation: sandboxed agents can reach external network only through sidecar path, and DNS resolution cannot bypass Firma-controlled routing.

## Scope

### In Scope
- Sandbox-local bridge to sidecar endpoint (UDS/TCP bridge pattern)
- Network namespace egress lockdown semantics
- Generated resolver config and sandbox-local DNS stub
- Sidecar outage fail-closed behavior (startup + mid-session)

### Out of Scope
- Capability claim semantics (Unit 004)
- Profile-specific tuning (Unit 005)

---

## Assigned Requirements

| FR | Requirement | Priority |
|----|-------------|----------|
| FR-4 | Structural Outbound Routing | Must |
| FR-5 | DNS Confinement | Must |

---

## Domain Concepts

### Key Entities
| Entity | Description | Attributes |
|--------|-------------|------------|
| EgressBridge | Local proxy bridge inside sandbox | listen addr, sidecar endpoint, health |
| ResolverPlan | Generated DNS confinement plan | resolv.conf contents, local stub bind |
| ConfinementState | Enforced network state | direct egress blocked, sidecar path allowed |

### Key Operations
| Operation | Description | Inputs | Outputs |
|-----------|-------------|--------|---------|
| start_egress_bridge | Start sandbox-local mediation bridge | sidecar endpoint | bridge handle |
| apply_confinement | Enforce network restrictions | backend handle | confinement proof |
| start_dns_stub | Start DNS stub and wire resolver | resolver plan | dns handle |

---

## Story Summary

| Metric | Count |
|--------|-------|
| Total Stories | 4 |
| Must Have | 4 |
| Should Have | 0 |
| Could Have | 0 |

### Stories

| Story ID | Title | Priority | Status |
|----------|-------|----------|--------|
| 001-sidecar-uds-bridge | Sidecar bridge in sandbox | Must | Planned |
| 002-network-egress-lockdown | No-bypass egress confinement | Must | Planned |
| 003-dns-stub-and-resolver-wiring | DNS confinement implementation | Must | Planned |
| 004-sidecar-unreachable-zero-egress | Outage fail-closed behavior | Must | Planned |

---

## Dependencies

### Depends On
| Unit | Reason |
|------|--------|
| 002-bwrap-backend-contract | Needs prepared sandbox runtime |

### Depended By
| Unit | Reason |
|------|--------|
| 006-e2e-bench-and-docs | E2E security assertions depend on this unit |

---

## Constraints

- No direct external network success path outside sidecar mediation
- DNS cannot use host ambient resolver path
- Startup and runtime must fail closed when sidecar path is unavailable

## Success Criteria

### Functional
- [ ] All successful outbound HTTP traffic is sidecar-mediated
- [ ] Direct network attempts fail from sandbox
- [ ] DNS queries route through sandbox-local resolver path
- [ ] Sidecar outage yields zero external egress

### Quality
- [ ] E2E tests cover bypass attempts (`curl`, explicit DNS probes)
- [ ] Deterministic diagnostics explain deny/connection failures
