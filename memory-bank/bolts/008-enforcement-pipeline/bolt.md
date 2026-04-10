---
id: 008-enforcement-pipeline
unit: 002-enforcement-pipeline
intent: 006-sidecar-proxy-enforcement
type: ddd-construction-bolt
status: complete
stories:
  - 001-intent-normalizer
  - 002-unclassified-intent-denial
  - 003-stage1-token-validation
  - 004-stage2-cedar-evaluation
  - 005-two-phase-pipeline-integration
created: 2026-04-05T12:00:00.000Z
started: 2026-04-05T14:00:00.000Z
completed: "2026-04-05T09:27:29Z"
current_stage: null
stages_completed:
  - name: domain-model
    completed: 2026-04-05T15:00:00.000Z
    artifact: ddd-01-domain-model.md
  - name: technical-design
    completed: 2026-04-05T16:00:00.000Z
    artifact: ddd-02-technical-design.md
  - name: adr-analysis
    completed: 2026-04-05T16:30:00.000Z
    artifact: adr-001-evolve-firma-core-types.md
  - name: implement
    completed: 2026-04-05T18:00:00.000Z
    artifact: crates/firma-sidecar/src/enforcement/
  - name: test
    completed: 2026-04-05T19:00:00.000Z
    artifact: ddd-03-test-report.md
requires_bolts: []
enables_bolts:
  - 011-llm-response-parser
requires_units: []
blocks: false
complexity:
  avg_complexity: 3
  avg_uncertainty: 2
  max_dependencies: 2
  testing_scope: 3
---

# Bolt: 008-enforcement-pipeline

## Overview

Single bolt covering the entire two-phase enforcement pipeline — intent normalization, Stage 1 capability validation, Stage 2 Cedar policy evaluation, and the integrated enforce() entry point.

## Objective

Build the core decision engine: deterministic intent normalization with all 15 action classes, PASETO v4 token validation with revocation checking, Cedar context building with configurable schema, policy evaluation, scope checking, and the unified two-phase pipeline.

## Stories Included

- **001-intent-normalizer**: Mapping table + action class registry → ExecutionEnvelope (Must)
- **002-unclassified-intent-denial**: DENY: UNCLASSIFIED_INTENT for unmappable actions (Must)
- **003-stage1-token-validation**: PASETO v4 parse, verify, expiry, revocation (Must)
- **004-stage2-cedar-evaluation**: Cedar context build + policy eval + scope check (Must)
- **005-two-phase-pipeline-integration**: Wire Stage 1 → Stage 2, unified Decision (Must)

## Bolt Type

**Type**: DDD Construction Bolt
**Definition**: `.specsmd/aidlc/templates/construction/bolt-types/ddd-construction-bolt.md`

## Stages

- [ ] **1. Domain Model**: Pending → ddd-01-domain-model.md
- [ ] **2. Technical Design**: Pending → ddd-02-technical-design.md
- [ ] **3. Implementation**: Pending → src/firma-sidecar/
- [ ] **4. Test & Verify**: Pending → ddd-03-test-report.md

## Dependencies

### Requires
- None (uses firma-core traits, independent implementation)

### Enables
- 011-llm-response-parser (needs enforcement pipeline for tool call evaluation)

## Success Criteria

- [ ] All 15 action classes supported in mapping configuration
- [ ] DENY: UNCLASSIFIED_INTENT for unmappable protected actions
- [ ] PASETO v4 tokens validated (parse, verify, expiry, revocation)
- [ ] Cedar context includes base, sidecar-managed, and custom attributes
- [ ] Deterministic evaluation: same context + bundle = same result
- [ ] Stage 1 < 1ms p95, Stage 2 < 200µs p95
- [ ] Two-phase pipeline short-circuits on Stage 1 failure
- [ ] Every error path ends in DENY (fail-closed)

## Notes

- This is the highest-value bolt — the core enforcement logic that everything else depends on
- Cedar context schema-contract tests are critical (silent non-match is invisible)
- 5 stories is at the upper limit but they're tightly cohesive — splitting would create artificial boundaries
- The enforce() interface is reused by both proxy-core (request-path) and llm-response-parser (response-path)
