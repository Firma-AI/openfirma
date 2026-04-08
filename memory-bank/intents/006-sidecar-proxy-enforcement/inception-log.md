---
intent: 006-sidecar-proxy-enforcement
created: 2026-04-04T12:00:00Z
completed: 2026-04-05T12:30:00Z
status: complete
---

# Inception Log: sidecar-proxy-enforcement

## Overview

**Intent**: Real `firma-sidecar` — Pingora HTTP proxy with two-phase enforcement (Stage 1 + Stage 2/CEE), LLM response-path evaluation, generic HTTP connector, credential injector, audit emitter
**Type**: green-field
**Created**: 2026-04-04

## Artifacts Created

| Artifact | Status | File |
|----------|--------|------|
| Requirements | ✅ approved | requirements.md |
| System Context | ✅ approved | system-context.md |
| Units | ✅ approved | units.md |
| Unit Briefs | ✅ approved | units/*/unit-brief.md (6 units) |
| Stories | ✅ approved | units/*/stories/*.md (28 stories) |
| Bolt Plan | ✅ approved | memory-bank/bolts/006-013 (8 bolts) |

## Summary

| Metric | Count |
|--------|-------|
| Functional Requirements | 13 |
| Non-Functional Requirements | 4 categories (Performance, Memory, Security, Reliability) |
| Units | 6 |
| Stories | 28 |
| Bolts Planned | 8 |

## Units Breakdown

| Unit | Stories | Bolts | Priority |
|------|---------|-------|----------|
| 001-proxy-core | 6 | 2 (006, 007) | Must |
| 002-enforcement-pipeline | 5 | 1 (008) | Must |
| 003-policy-revocation | 5 | 2 (009, 010) | Must |
| 004-llm-response-parser | 5 | 1 (011) | Must |
| 005-connector-credentials | 3 | 1 (012) | Must |
| 006-audit-observability | 4 | 1 (013) | Must (3) + Should (1) |

## Decision Log

| Date | Decision | Rationale | Approved |
|------|----------|-----------|----------|
| 2026-04-05 | V1 audit delivery is best-effort async only | Event loss on crash acceptable; WAL/durable sinks are post-V1 | Yes (team) |
| 2026-04-05 | 6-unit decomposition with domain-driven boundaries | Each unit has single responsibility, can be built/tested independently | Yes |
| 2026-04-05 | 8 bolts (DDD type) covering all 28 stories | Bolt sizing 2-6 stories per bolt; dependency graph respects build order | Yes |
| 2026-04-05 | OpenAI parser targets Responses API as primary + Chat Completions | Responses API is current; Chat Completions retained for compatibility | Yes |

## Scope Changes

| Date | Change | Reason | Impact |
|------|--------|--------|--------|
| 2026-04-05 | Added explicit V1 audit delivery guarantee to requirements | Colleague feedback on WAL/audit | Updated FR-10, Reliability NFR, Out of Scope |
| 2026-04-05 | OpenAI parser expanded to cover Responses API | User feedback at Checkpoint 3 | Updated FR-7, story 001-openai-parser |

## Ready for Construction

**Checklist**:
- [x] All requirements documented
- [x] System context defined
- [x] Units decomposed
- [x] Stories created for all units
- [x] Bolts planned
- [x] Human review complete

## Next Steps

1 - **construction**: Start building with first bolt

→ `/specsmd-construction-agent --unit="002-enforcement-pipeline" --bolt-id="008-enforcement-pipeline"`

## Dependencies

Depends on intents 002 (core types) and 003 (gRPC protocol).
