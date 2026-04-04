---
id: 009-policy-revocation
unit: 003-policy-revocation
intent: 006-sidecar-proxy-enforcement
type: ddd-construction-bolt
status: planned
stories:
  - 001-file-policy-source
  - 003-file-revocation-source
  - 005-revocation-cache
created: 2026-04-05T12:00:00Z
started: null
completed: null
current_stage: null
stages_completed: []

requires_bolts: []
enables_bolts: [010-policy-revocation]
requires_units: []
blocks: false

complexity:
  avg_complexity: 2
  avg_uncertainty: 1
  max_dependencies: 1
  testing_scope: 2
---

# Bolt: 009-policy-revocation

## Overview

First bolt for policy and revocation — file-based sources and the shared revocation cache. Establishes standalone operation mode.

## Objective

Implement file-based PolicySource (load, watch, hot-reload), file-based RevocationSource (JSON file, watch), and the two-layer revocation cache (bloom filter + LRU). This enables Sidecar development and testing without a running Authority.

## Stories Included

- **001-file-policy-source**: Load .cedar files, watch, hot-reload, malformed rejection (Must)
- **003-file-revocation-source**: JSON file-based revocation with filesystem watch (Must)
- **005-revocation-cache**: Bloom filter + LRU two-layer cache for O(1) checks (Must)

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
- None (independent data source implementation)

### Enables
- 010-policy-revocation (gRPC sources build on same traits)

## Success Criteria

- [ ] File mode loads all .cedar files at startup
- [ ] Hot-reload within 500ms of filesystem change
- [ ] Malformed files: fail-fast at startup, retain valid on reload
- [ ] File revocation entries loaded from JSON
- [ ] Bloom filter provides sub-microsecond negative check
- [ ] LRU stores confirmed revocations
- [ ] Thread-safe concurrent reads

## Notes

- Build revocation cache (story 005) first — it's shared by both file and gRPC sources
- File mode is explicitly a temporary mechanism for dev/testing while Mini Authority (intent 005) isn't complete
- PolicySource and RevocationSource traits must be clean for community extension
