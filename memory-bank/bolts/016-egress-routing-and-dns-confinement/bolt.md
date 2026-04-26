---
id: 016-egress-routing-and-dns-confinement
unit: 003-egress-routing-and-dns-confinement
intent: 007-firma-run-sandbox-launcher
type: ddd-construction-bolt
status: planned
stories:
  - 001-sidecar-uds-bridge
  - 002-network-egress-lockdown
created: 2026-04-26T12:00:00Z
started: null
completed: null
current_stage: null
stages_completed: []

requires_bolts: [015-bwrap-backend-contract]
enables_bolts: [017-egress-routing-and-dns-confinement]
requires_units: [002-bwrap-backend-contract]
blocks: true

complexity:
  avg_complexity: 3
  avg_uncertainty: 2
  max_dependencies: 2
  testing_scope: 3
---

# Bolt: 016-egress-routing-and-dns-confinement

## Overview

First security-critical confinement bolt: sidecar bridge and direct-egress lockdown.

## Objective

Guarantee structural mediation path by making sidecar bridge mandatory and direct network bypass impossible.
