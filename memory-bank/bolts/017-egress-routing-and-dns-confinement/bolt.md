---
id: 017-egress-routing-and-dns-confinement
unit: 003-egress-routing-and-dns-confinement
intent: 007-firma-run-sandbox-launcher
type: ddd-construction-bolt
status: planned
stories:
  - 003-dns-stub-and-resolver-wiring
  - 004-sidecar-unreachable-zero-egress
created: 2026-04-26T12:00:00Z
started: null
completed: null
current_stage: null
stages_completed: []

requires_bolts: [016-egress-routing-and-dns-confinement]
enables_bolts: [020-e2e-bench-and-docs]
requires_units: [003-egress-routing-and-dns-confinement]
blocks: true

complexity:
  avg_complexity: 3
  avg_uncertainty: 3
  max_dependencies: 2
  testing_scope: 3
---

# Bolt: 017-egress-routing-and-dns-confinement

## Overview

Second confinement bolt: DNS path closure and sidecar-outage fail-closed proofs.

## Objective

Implement explicit resolver confinement and prove zero external egress when sidecar is unavailable.
