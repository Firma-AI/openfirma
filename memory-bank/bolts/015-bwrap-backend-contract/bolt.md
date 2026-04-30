---
id: 015-bwrap-backend-contract
unit: 002-bwrap-backend-contract
intent: 007-firma-run-sandbox-launcher
type: ddd-construction-bolt
status: planned
stories:
  - 001-backend-trait-and-proof-objects
  - 002-bwrap-sandbox-launcher
  - 003-enterprise-backend-extension-seam
created: 2026-04-26T12:00:00Z
started: null
completed: null
current_stage: null
stages_completed: []

requires_bolts: [014-cli-runtime-orchestrator]
enables_bolts: [016-egress-routing-and-dns-confinement, 018-identity-and-capability-lifecycle]
requires_units: [001-cli-runtime-orchestrator]
blocks: true

complexity:
  avg_complexity: 2
  avg_uncertainty: 2
  max_dependencies: 2
  testing_scope: 2
---

# Bolt: 015-bwrap-backend-contract

## Overview

Linux backend contract and bubblewrap runtime implementation seam for FIR-61.

## Objective

Define backend interface, implement bwrap runtime lifecycle, and keep extension seam for enterprise profiles.
