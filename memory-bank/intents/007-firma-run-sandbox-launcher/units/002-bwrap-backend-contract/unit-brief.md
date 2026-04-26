---
unit: 002-bwrap-backend-contract
intent: 007-firma-run-sandbox-launcher
phase: inception
status: ready
created: 2026-04-26T12:00:00Z
updated: 2026-04-26T12:00:00Z
---

# Unit Brief: bwrap Backend Contract

## Purpose

Define and implement the FIR-60 backend contract for FIR-61 Linux scope using bubblewrap, while keeping extension seams for enterprise profiles.

## Scope

### In Scope
- Backend trait and invariant proof artifacts
- Linux bubblewrap backend (`prepare`, `start_agent`, `teardown`, checks)
- Explicit unsupported behavior for non-Linux FIR-61 execution

### Out of Scope
- Network confinement internals (Unit 003)
- Profile defaults (Unit 005)
- Benchmarks and docs (Unit 006)

---

## Assigned Requirements

| FR | Requirement | Priority |
|----|-------------|----------|
| FR-3 | Backend Contract and Linux bwrap Backend | Must |

---

## Domain Concepts

### Key Entities
| Entity | Description | Attributes |
|--------|-------------|------------|
| SandboxBackend | Runtime backend interface | prepare/enforce/start/verify/teardown |
| BwrapBackend | Linux bubblewrap implementation | paths, namespace args, mounts |
| EnforcementProof | Captured invariants from setup | backend ready, confinement mode |

### Key Operations
| Operation | Description | Inputs | Outputs |
|-----------|-------------|--------|---------|
| prepare | Validate host/runtime prerequisites | runtime config | SandboxHandle |
| start_agent | Launch wrapped command in sandbox | SandboxHandle, command | AgentHandle |
| teardown | Cleanup runtime resources | handles | Result |

---

## Story Summary

| Metric | Count |
|--------|-------|
| Total Stories | 3 |
| Must Have | 3 |
| Should Have | 0 |
| Could Have | 0 |

### Stories

| Story ID | Title | Priority | Status |
|----------|-------|----------|--------|
| 001-backend-trait-and-proof-objects | Backend trait and proof model | Must | Planned |
| 002-bwrap-sandbox-launcher | Linux bwrap implementation | Must | Planned |
| 003-enterprise-backend-extension-seam | Firecracker/profile seam | Must | Planned |

---

## Dependencies

### Depends On
| Unit | Reason |
|------|--------|
| 001-cli-runtime-orchestrator | Backend selected and driven by CLI runtime |

### Depended By
| Unit | Reason |
|------|--------|
| 003-egress-routing-and-dns-confinement | Confinement built on backend runtime |
| 004-identity-and-capability-lifecycle | Identity ties to backend lifecycle |

---

## Constraints

- Linux-only implementation in FIR-61
- bubblewrap remains external runtime dependency
- Unsupported backends must fail clearly, not silently fallback

## Success Criteria

### Functional
- [ ] Backend interface implemented and tested
- [ ] bwrap launch path works for wrapped command
- [ ] Preflight detects missing kernel/tool prerequisites

### Quality
- [ ] Backend lifecycle tests cover prepare/start/teardown
- [ ] Invariant proofs captured for diagnostics
