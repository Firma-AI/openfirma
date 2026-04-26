---
id: 014-cli-runtime-orchestrator
unit: 001-cli-runtime-orchestrator
intent: 007-firma-run-sandbox-launcher
type: ddd-construction-bolt
status: planned
stories:
  - 001-cli-surface-and-arg-parsing
  - 002-process-supervision-and-signal-forwarding
  - 003-tui-safe-stdio-passthrough
  - 004-fail-closed-startup-order
created: 2026-04-26T12:00:00Z
started: null
completed: null
current_stage: null
stages_completed: []

requires_bolts: []
enables_bolts: [015-bwrap-backend-contract, 019-profiles-and-config]
requires_units: []
blocks: true

complexity:
  avg_complexity: 2
  avg_uncertainty: 1
  max_dependencies: 1
  testing_scope: 2
---

# Bolt: 014-cli-runtime-orchestrator

## Overview

Foundational bolt for FIR-61 runtime orchestration and interactive-safe CLI behavior.

## Objective

Implement `firma run` command parsing, supervision lifecycle, signal forwarding, and fail-closed startup ordering.
