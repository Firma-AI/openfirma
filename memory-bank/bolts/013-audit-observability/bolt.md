---
id: 013-audit-observability
unit: 006-audit-observability
intent: 006-sidecar-proxy-enforcement
type: ddd-construction-bolt
status: planned
stories:
  - 001-execution-event-schema
  - 002-ecdsa-audit-signing
  - 003-audit-sinks
  - 004-prometheus-metrics
created: 2026-04-05T12:00:00Z
started: null
completed: null
current_stage: null
stages_completed: []

requires_bolts: []
enables_bolts: []
requires_units: []
blocks: false

complexity:
  avg_complexity: 2
  avg_uncertainty: 1
  max_dependencies: 1
  testing_scope: 2
---

# Bolt: 013-audit-observability

## Overview

Single bolt for audit event emission and Prometheus metrics — ExecutionEvent schema, ECDSA signing, sink implementations, and metrics endpoint.

## Objective

Build the observability layer: ExecutionEvent with all FEP §15 fields, ECDSA signature computation, stdout + file audit sinks with async non-blocking emission, and Prometheus /metrics endpoint with decision counters, latency histograms, and operational gauges.

## Stories Included

- **001-execution-event-schema**: ExecutionEvent with all FEP §15 fields (Must)
- **002-ecdsa-audit-signing**: ECDSA signature over event fields (Must)
- **003-audit-sinks**: stdout + file sinks, multi-sink, async non-blocking (Must)
- **004-prometheus-metrics**: /metrics endpoint, counters, histograms, gauges (Should)

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
- None (receives events from enforcement pipeline via async channel)

### Enables
- None (integrated by proxy-core after every enforcement decision)

## Success Criteria

- [ ] Every decision emits an audit event (no silent paths)
- [ ] All FEP §15 minimum fields present
- [ ] ECDSA signature verifiable with public key
- [ ] stdout sink: one JSON line per event, jq-compatible
- [ ] file sink: append-only to configurable path
- [ ] Multiple sinks active simultaneously
- [ ] Emission does not block enforcement
- [ ] /metrics returns Prometheus exposition format
- [ ] All required counters, histograms, gauges present

## Notes

- V1 audit delivery is best-effort async — event loss on crash is acceptable (team decision)
- Audit signing key is separate from TLS CA keypair
- Prometheus metrics provide real-time view; audit events provide (best-effort) durable trail
- Pending events must flush on graceful shutdown
