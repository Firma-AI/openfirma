---
unit: 006-e2e-bench-and-docs
intent: 007-firma-run-sandbox-launcher
phase: inception
status: ready
created: 2026-04-26T12:00:00Z
updated: 2026-04-26T12:00:00Z
---

# Unit Brief: E2E, Benchmarks, and Docs

## Purpose

Produce launch-grade verification and evidence for FIR-61: interception behavior, fail-closed invariants, benchmark artifacts, and user-facing documentation.

## Scope

### In Scope
- E2E tests for `generic` and `codex` profiles
- Sidecar-mediated and deny-surface behavior tests
- Benchmark harness and artifact output
- README/docs updates for FIR-61 positioning

### Out of Scope
- New runtime policy engine logic
- FIR-62 profile specialization

---

## Assigned Requirements

| FR | Requirement | Priority |
|----|-------------|----------|
| FR-10 | Integration Tests and Security Assertions | Must |
| FR-11 | Benchmark Harness and Artifacts | Must |
| FR-12 | Documentation and Positioning | Must |

---

## Domain Concepts

### Key Entities
| Entity | Description | Attributes |
|--------|-------------|------------|
| E2EScenario | End-to-end test scenario | profile, command, expected mediation |
| BenchmarkRun | Performance measurement batch | startup timings + request deltas |
| EvidenceBundle | Output artifact set | JSON metrics + markdown summary |

### Key Operations
| Operation | Description | Inputs | Outputs |
|-----------|-------------|--------|---------|
| run_e2e_matrix | Execute profile interception tests | scenario matrix | pass/fail report |
| run_benchmarks | Collect startup/overhead metrics | benchmark config | benchmark JSON |
| publish_docs | Update user/operator docs | outcomes + examples | updated markdown |

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
| 001-generic-profile-e2e | Generic profile E2E suite | Must | Planned |
| 002-codex-profile-e2e | Codex profile E2E suite | Must | Planned |
| 003-benchmark-harness-and-json-artifacts | Benchmark harness + artifacts | Must | Planned |
| 004-readme-and-ops-guide | Documentation updates | Must | Planned |

---

## Dependencies

### Depends On
| Unit | Reason |
|------|--------|
| 003-egress-routing-and-dns-confinement | Security assertions require confinement implementation |
| 004-identity-and-capability-lifecycle | Attribution and lease scenarios depend on this unit |
| 005-profiles-and-config | Profile matrix depends on config resolution |

### Depended By
| Unit | Reason |
|------|--------|
| None | Final integration/documentation unit |

---

## Constraints

- Benchmarks must emit machine-readable JSON under `target/benchmarks/firma-run/`
- E2E suite must include sidecar-unreachable fail-closed assertions
- Docs must clearly separate FIR-61 and FIR-62 scope

## Success Criteria

### Functional
- [ ] Both profile E2E suites pass
- [ ] Benchmark artifacts generated and reproducible
- [ ] README quickstart covers FIR-61 flow

### Quality
- [ ] E2E tests are CI-runnable (with Linux gating where needed)
- [ ] Benchmark schema is stable and parseable
