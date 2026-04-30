---
id: 003-benchmark-harness-and-json-artifacts
unit: 006-e2e-bench-and-docs
intent: 007-firma-run-sandbox-launcher
status: ready
priority: must
created: 2026-04-26T12:00:00Z
assigned_bolt: 020-e2e-bench-and-docs
implemented: false
---

# Story: 003-benchmark-harness-and-json-artifacts

## User Story

**As an** engineering lead
**I want** benchmark artifacts for startup and mediation overhead
**So that** launch performance claims are evidence-backed

## Acceptance Criteria

- [ ] **Given** benchmark harness runs, **When** execution completes, **Then** JSON artifacts are written under `target/benchmarks/firma-run/`
- [ ] **Given** startup benchmark scenario, **When** measured, **Then** it captures `t_backend_ready`, `t_sidecar_ready`, `t_first_request`
- [ ] **Given** request benchmark scenario, **When** measured, **Then** it reports p50/p95/p99 deltas for generic and codex profiles
- [ ] **Given** benchmark output schema, **When** consumed by docs/scripts, **Then** fields are stable and parseable

## Technical Notes

- Provide repeat count and warmup controls
- Include environment metadata in output
- Keep benchmark harness deterministic enough for regression checks

## Dependencies

### Requires
- 001-generic-profile-e2e
- 002-codex-profile-e2e

### Enables
- 004-readme-and-ops-guide

## Edge Cases

| Scenario | Expected Behavior |
|----------|-------------------|
| Benchmark run interrupted | Partial artifact marked incomplete |
| Sidecar outage scenario benchmarked | Recorded as fail-closed evidence, not success latency |
| Profile-specific setup missing | Benchmark fails with actionable setup diagnostics |

## Out of Scope

- Hard CI perf gate policy
