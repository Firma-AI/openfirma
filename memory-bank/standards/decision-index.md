---
last_updated: 2026-04-05T17:00:00Z
total_decisions: 3
---

# Decision Index

This index tracks all Architecture Decision Records (ADRs) created during Construction bolts.
Use this to find relevant prior decisions when working on related features.

## How to Use

**For Agents**: Scan the "Read when" fields below to identify decisions relevant to your current task. Before implementing new features, check if existing ADRs constrain or guide your approach. Load the full ADR for matching entries.

**For Humans**: Browse decisions chronologically or search for keywords. Each entry links to the full ADR with complete context, alternatives considered, and consequences.

---

## Decisions

### ADR-001: Use `pasetors` instead of `rusty_paseto` for PASETO v4
- **Status**: accepted
- **Date**: 2026-03-28
- **Bolt**: 003-paseto-v4 (paseto-v4)
- **Path**: `bolts/003-paseto-v4/adr-001-pasetors-over-rusty-paseto.md`
- **Summary**: Tech stack specified `rusty_paseto` but research revealed `pasetors` is significantly stronger. Use `pasetors` 0.7.8 for all PASETO v4.public operations.
- **Read when**: Working on token signing, token verification, PASETO tokens, or adding crypto dependencies to firma-core

### ADR-001: Evolve firma-core types to match enforcement pipeline requirements
- **Status**: accepted
- **Date**: 2026-04-05
- **Bolt**: 008-enforcement-pipeline (enforcement-pipeline)
- **Path**: `bolts/008-enforcement-pipeline/adr-001-evolve-firma-core-types.md`
- **Summary**: firma-core's ExecutionIntent is missing action_class, raw_transport, raw_action_ref. Update firma-core types rather than creating sidecar-local duplicates. Keep PolicyEvaluator simple; sidecar uses cedar-policy directly.
- **Read when**: Modifying ExecutionEnvelope or ExecutionIntent, working on the enforcement pipeline, adding new DenyReason variants, or implementing PolicyEvaluator

### ADR-002: Sidecar-managed capability map for token selection
- **Status**: accepted
- **Date**: 2026-04-05
- **Bolt**: 008-enforcement-pipeline (enforcement-pipeline)
- **Path**: `bolts/008-enforcement-pipeline/adr-002-capability-map-token-selection.md`
- **Summary**: Agent is transparent (knows nothing about Firma). Sidecar holds multiple capability tokens in a map, selects by (session_id, action_class, resource) after intent normalization. Dual-mode: file for dev, Authority for production.
- **Read when**: Working on token selection, enforce() API, capability provisioning, session management, or sidecar startup lifecycle
