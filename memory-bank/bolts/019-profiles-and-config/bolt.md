---
id: 019-profiles-and-config
unit: 005-profiles-and-config
intent: 007-firma-run-sandbox-launcher
type: ddd-construction-bolt
status: planned
stories:
  - 001-config-schema-and-validation
  - 002-generic-profile-default
  - 003-codex-profile-default
  - 004-mount-env-passthrough-rules
created: 2026-04-26T12:00:00Z
started: null
completed: null
current_stage: null
stages_completed: []

requires_bolts: [014-cli-runtime-orchestrator]
enables_bolts: [020-e2e-bench-and-docs]
requires_units: [001-cli-runtime-orchestrator]
blocks: false

complexity:
  avg_complexity: 2
  avg_uncertainty: 1
  max_dependencies: 2
  testing_scope: 2
---

# Bolt: 019-profiles-and-config

## Overview

Config schema and built-in profile defaults for FIR-61 day-one UX.

## Objective

Deliver typed config validation and complete `generic`/`codex` profile definitions with explicit passthrough policies.
