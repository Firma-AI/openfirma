---
unit: 005-profiles-and-config
intent: 007-firma-run-sandbox-launcher
phase: inception
status: ready
created: 2026-04-26T12:00:00Z
updated: 2026-04-26T12:00:00Z
---

# Unit Brief: Profiles and Config

## Purpose

Provide a stable configuration contract and built-in profile defaults (`generic`, `codex`) that minimize setup while preserving explicit security controls.

## Scope

### In Scope
- Config schema and parser validation
- Built-in profile definitions
- Merge logic: built-in defaults + file overrides + CLI overrides
- Mount and env passthrough allowlist model

### Out of Scope
- Backend isolation internals
- E2E benchmark artifacts

---

## Assigned Requirements

| FR | Requirement | Priority |
|----|-------------|----------|
| FR-7 | Config Schema and Policy Knobs | Must |
| FR-8 | Built-in Profiles (`generic`, `codex`) | Must |

---

## Domain Concepts

### Key Entities
| Entity | Description | Attributes |
|--------|-------------|------------|
| RunConfig | Fully resolved runtime config | profile + overrides |
| ProfileDefinition | Built-in profile defaults | mounts, env passthrough, sidecar endpoint |
| PassthroughRuleSet | Env/path allowlist | allow, deny, required |

### Key Operations
| Operation | Description | Inputs | Outputs |
|-----------|-------------|--------|---------|
| load_config | Load file + defaults | file path + profile | RunConfig |
| validate_config | Validate schema and constraints | RunConfig | pass/fail diagnostics |
| resolve_profile | Select built-in profile defaults | profile id | ProfileDefinition |

---

## Story Summary

| Metric | Count |
|--------|-------|
| Total Stories | 4 |
| Must Have | 4 |
| Should Have | 0 |
| Could Have | 0 |

### Stories

| Story ID | Title | Priority | Status |
|----------|-------|----------|--------|
| 001-config-schema-and-validation | Config schema and validation | Must | Planned |
| 002-generic-profile-default | Generic profile defaults | Must | Planned |
| 003-codex-profile-default | Codex profile defaults | Must | Planned |
| 004-mount-env-passthrough-rules | Mount/env policy rules | Must | Planned |

---

## Dependencies

### Depends On
| Unit | Reason |
|------|--------|
| 001-cli-runtime-orchestrator | CLI selects profile/config |

### Depended By
| Unit | Reason |
|------|--------|
| 006-e2e-bench-and-docs | Test and benchmark matrix depends on resolved profiles |

---

## Constraints

- Unknown config fields must fail-fast
- Default profile must be `generic`
- `codex` profile must remain FIR-61 generic wrapper, not FIR-62 specialization

## Success Criteria

### Functional
- [ ] Config and profile resolution deterministic
- [ ] Both built-in profiles runnable out-of-box
- [ ] Mount/env passthrough rules enforce allowlist semantics

### Quality
- [ ] Schema validation tests cover invalid/unknown fields
- [ ] Profile fixtures are versioned and regression-tested
