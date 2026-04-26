---
id: 018-identity-and-capability-lifecycle
unit: 004-identity-and-capability-lifecycle
intent: 007-firma-run-sandbox-launcher
type: ddd-construction-bolt
status: planned
stories:
  - 001-deterministic-sandbox-id
  - 002-attribution-header-injection
  - 003-capability-rotation-contract
created: 2026-04-26T12:00:00Z
started: null
completed: null
current_stage: null
stages_completed: []

requires_bolts: [015-bwrap-backend-contract]
enables_bolts: [020-e2e-bench-and-docs]
requires_units: [002-bwrap-backend-contract]
blocks: false

complexity:
  avg_complexity: 2
  avg_uncertainty: 2
  max_dependencies: 2
  testing_scope: 2
---

# Bolt: 018-identity-and-capability-lifecycle

## Overview

Identity attribution and long-running capability renewal semantics.

## Objective

Implement deterministic run identity propagation and renewable capability source contract for persistent agents.
