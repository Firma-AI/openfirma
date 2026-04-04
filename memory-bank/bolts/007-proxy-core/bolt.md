---
id: 007-proxy-core
unit: 001-proxy-core
intent: 006-sidecar-proxy-enforcement
type: ddd-construction-bolt
status: planned
stories:
  - 004-proxy-denial-response-format
  - 005-config-and-startup
  - 006-health-readiness-shutdown
created: 2026-04-05T12:00:00Z
started: null
completed: null
current_stage: null
stages_completed: []

requires_bolts: [006-proxy-core]
enables_bolts: []
requires_units: []
blocks: false

complexity:
  avg_complexity: 2
  avg_uncertainty: 1
  max_dependencies: 1
  testing_scope: 2
---

# Bolt: 007-proxy-core

## Overview

Second bolt for proxy core — configuration, startup lifecycle, health/readiness endpoints, graceful shutdown, and proxy-path denial response formatting.

## Objective

Complete the proxy operational layer: TOML config with CLI overrides, fail-fast startup validation, /healthz and /readyz endpoints, SIGTERM graceful shutdown with drain, and Firma JSON denial response format.

## Stories Included

- **004-proxy-denial-response-format**: Firma JSON denial responses (Must)
- **005-config-and-startup**: TOML config + CLI overrides + fail-fast (Must)
- **006-health-readiness-shutdown**: Health, readiness, graceful shutdown (Must)

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
- 006-proxy-core (proxy transport must exist)

### Enables
- None (completes proxy-core unit)

## Success Criteria

- [ ] Denial responses follow Firma JSON schema (403/400/503)
- [ ] All reason codes supported
- [ ] TOML config loaded with CLI overrides
- [ ] Invalid config → fail-fast with clear error
- [ ] /healthz returns 200 when alive
- [ ] /readyz returns 200 only when fully ready
- [ ] SIGTERM → graceful drain + audit flush

## Notes

- Denial response format is shared across all enforcement paths
- Readiness check depends on policy source and credential provider initialization
- Graceful shutdown must flush audit events before exit
