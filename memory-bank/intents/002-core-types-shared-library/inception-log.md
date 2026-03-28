---
intent: 002-core-types-shared-library
created: 2026-03-26T14:00:00Z
completed: 2026-03-28T10:00:00Z
status: complete
---

# Inception Log: core-types-shared-library

## Overview

**Intent**: Build the real `firma-core` crate — capability tokens, policy evaluation contract, execution types, error types, and storage trait interfaces
**Type**: green-field
**Created**: 2026-03-26

## Artifacts Created

| Artifact | Status | File |
| -------- | ------ | ---- |
| Requirements | ✅ | requirements.md |
| System Context | ✅ | system-context.md |
| Units | ✅ | units.md |
| Unit Brief: types-and-traits | ✅ | units/001-types-and-traits/unit-brief.md |
| Unit Brief: paseto-v4 | ✅ | units/002-paseto-v4/unit-brief.md |
| Stories: types-and-traits | ✅ | units/001-types-and-traits/stories/*.md (4 stories) |
| Stories: paseto-v4 | ✅ | units/002-paseto-v4/stories/*.md (3 stories) |
| Bolt: 002-types-and-traits | ✅ | memory-bank/bolts/002-types-and-traits/bolt.md |
| Bolt: 003-paseto-v4 | ✅ | memory-bank/bolts/003-paseto-v4/bolt.md |

## Summary

| Metric | Count |
| ------ | ----- |
| Functional Requirements | 10 |
| Non-Functional Requirements | 3 |
| Units | 2 |
| Stories | 7 |
| Bolts Planned | 2 |

## Units Breakdown

| Unit | Stories | Bolts | Priority |
| ---- | ------- | ----- | -------- |
| 001-types-and-traits | 4 | 1 (002-types-and-traits) | Must |
| 002-paseto-v4 | 3 | 1 (003-paseto-v4) | Must |

## Decision Log

| Date | Decision | Rationale | Approved |
| ---- | -------- | --------- | -------- |
| 2026-03-26 | Rust-only Capability Library (no Go/Python/TS SDKs) | Agents interact via HTTP_PROXY — no agent-side SDK needed in V1 | Yes |
| 2026-03-26 | Trait interfaces only for storage (no implementations) | Later intents (005/006) provide real impls; tests can mock | Yes |
| 2026-03-26 | PolicyEvaluator trait with no Cedar dependency | Testability — mocks can substitute Cedar in unit tests. Cedar is an implementation detail of 005/006 | Yes |
| 2026-03-26 | PASETO v4 fully implemented, JWT RS256 deferred | PASETO is the primary format; JWT is a fallback. Trait makes JWT a drop-in later | Yes |
| 2026-03-26 | Execution Envelope in firma-core (not firma-proto) | Never crosses a network boundary — it's built and consumed locally in the Sidecar | Yes |
| 2026-03-26 | Cedar entity mappings deferred to 005/006 | Domain fields already in Envelope/Context; Cedar-specific conversion needs cedar-policy dep | Yes |
| 2026-03-26 | Error types scoped to firma-core only | Each crate defines its own errors per coding standards; firma-core errors cover tokens and evaluation | Yes |
| 2026-03-26 | Shared types only for Cedar wrapper (Option B) | firma-core provides ExecutionContext and Decision types; actual Cedar eval logic in 005/006 | Yes |
| 2026-03-28 | Typed action params (HttpParams/DbQueryParams/ToolUseParams) instead of generic map | PR #5 review: generic Struct allows injection attacks. Typed oneof enforces schema at proto level | Yes |
| 2026-03-28 | Remove budget_consumed from ExecutionMetadata | PR #5 review: unclear how to compute/track. Defer until mechanism is designed | Yes |
| 2026-03-28 | Remove risk_score from ExecutionMetadata | PR #5 review: defer until anomaly detection model exists | Yes |
| 2026-03-28 | Remove provenance field from ExecutionEnvelope | PR #5 review: V1 placeholder with no implementation, confusing. Add back when designed | Yes |
| 2026-03-28 | Defer BudgetExceeded and RiskThreshold deny reasons | Corresponding fields removed; deny reasons re-added when fields return | Yes |

## Scope Changes

| Date | Change | Reason | Impact |

## Ready for Construction

**Checklist**:
- [x] All requirements documented
- [x] System context defined
- [x] Units decomposed
- [x] Stories created for all units
- [x] Bolts planned
- [x] Human review complete

## Next Steps

1. Human review of all artifacts (Checkpoint 3)
2. Begin Construction Phase
3. Start with Bolt: 002-types-and-traits
4. Execute: `/specsmd-construction-agent --intent="002-core-types-shared-library"`

## Dependencies

Depends on intent 001 (project scaffolding) — complete.

Bolt execution order:
```text
[002-types-and-traits] ──> [003-paseto-v4]
```
