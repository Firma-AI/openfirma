---
last_updated: 2026-03-28T11:10:00Z
total_decisions: 1
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
