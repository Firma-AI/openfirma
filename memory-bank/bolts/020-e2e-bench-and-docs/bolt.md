---
id: 020-e2e-bench-and-docs
unit: 006-e2e-bench-and-docs
intent: 007-firma-run-sandbox-launcher
type: ddd-construction-bolt
status: planned
stories:
  - 001-generic-profile-e2e
  - 002-codex-profile-e2e
  - 003-benchmark-harness-and-json-artifacts
  - 004-readme-and-ops-guide
created: 2026-04-26T12:00:00Z
started: null
completed: null
current_stage: null
stages_completed: []

requires_bolts: [017-egress-routing-and-dns-confinement, 018-identity-and-capability-lifecycle, 019-profiles-and-config]
enables_bolts: []
requires_units: [003-egress-routing-and-dns-confinement, 004-identity-and-capability-lifecycle, 005-profiles-and-config]
blocks: false

complexity:
  avg_complexity: 2
  avg_uncertainty: 2
  max_dependencies: 3
  testing_scope: 3
---

# Bolt: 020-e2e-bench-and-docs

## Overview

Final validation and evidence bolt for FIR-61 launch readiness.

## Objective

Run profile E2E matrix, emit benchmark artifacts, and update docs for FIR-61 usage and security behavior.
