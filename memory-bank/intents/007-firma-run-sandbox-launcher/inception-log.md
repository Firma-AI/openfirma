---
intent: 007-firma-run-sandbox-launcher
created: 2026-04-26T12:00:00Z
completed: 2026-04-26T12:00:00Z
status: complete
---

# Inception Log: firma-run-sandbox-launcher

## Overview

**Intent**: Build FIR-61 `firma-run` generic sandbox launcher with automatic sidecar routing
**Type**: green-field
**Created**: 2026-04-26

## Artifacts Created

| Artifact | Status | File |
|----------|--------|------|
| Requirements | ✅ approved | requirements.md |
| System Context | ✅ approved | system-context.md |
| Units | ✅ approved | units.md |
| Unit Briefs | ✅ approved | units/*/unit-brief.md (6 units) |
| Stories | ✅ approved | units/*/stories/*.md (22 stories) |
| Bolt Plan | ✅ approved | memory-bank/bolts/014-020 (7 bolts) |

## Summary

| Metric | Count |
|--------|-------|
| Functional Requirements | 12 |
| Non-Functional Requirement Categories | 4 |
| Units | 6 |
| Stories | 22 |
| Bolts Planned | 7 |

## Units Breakdown

| Unit | Stories | Bolts | Priority |
|------|---------|-------|----------|
| 001-cli-runtime-orchestrator | 4 | 014 | Must |
| 002-bwrap-backend-contract | 3 | 015 | Must |
| 003-egress-routing-and-dns-confinement | 4 | 016, 017 | Must |
| 004-identity-and-capability-lifecycle | 3 | 018 | Must |
| 005-profiles-and-config | 4 | 019 | Must |
| 006-e2e-bench-and-docs | 4 | 020 | Must |

## Decision Log

| Date | Decision | Rationale | Approved |
|------|----------|-----------|----------|
| 2026-04-26 | FIR-61 implementation is Linux-first with explicit pluggable backend contract | Align delivery timeline while preserving FIR-60 extensibility | Yes |
| 2026-04-26 | DNS confinement is explicit: generated resolver config + sandbox-local DNS stub over Firma-controlled path | Close known FIR-61 implementation ambiguity and bypass risk | Yes |
| 2026-04-26 | Long-running capability lifecycle is part of FIR-61 scope via renewable capability source contract | Prevent persistent-agent outages and unclear token-expiry semantics | Yes |
| 2026-04-26 | Sidecar remains single enforcement plane; wrapper is plumbing only | Preserve architecture from FIR-60/FIR-56 direction | Yes |

## Scope Changes

| Date | Change | Reason | Impact |
|------|--------|--------|--------|
| 2026-04-26 | Added explicit capability rotation requirement for persistent agents | Review feedback on OpenClaw-style always-on processes | +1 FR, +1 unit story |
| 2026-04-26 | Added explicit DNS implementation constraints | Review comment on resolver bypass gap | +1 FR, +1 unit story |

## Ready for Construction

**Checklist**:
- [x] All requirements documented
- [x] System context defined
- [x] Units decomposed
- [x] Stories created for all units
- [x] Bolts planned
- [x] Human review complete

## Next Steps

1. Start with `003-egress-routing-and-dns-confinement` architecture bolts after creating baseline CLI/backend scaffolding.
2. Execute:
   - `/specsmd-construction-agent --unit="001-cli-runtime-orchestrator" --bolt-id="014-cli-runtime-orchestrator"`
   - `/specsmd-construction-agent --unit="002-bwrap-backend-contract" --bolt-id="015-bwrap-backend-contract"`

## Dependencies

Construction order follows:

`001 -> (002,005) -> (003,004) -> 006`
