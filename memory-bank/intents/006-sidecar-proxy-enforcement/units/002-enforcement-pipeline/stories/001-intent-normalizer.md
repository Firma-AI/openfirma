---
id: 001-intent-normalizer
unit: 002-enforcement-pipeline
intent: 006-sidecar-proxy-enforcement
status: complete
priority: must
created: 2026-04-05T12:00:00.000Z
assigned_bolt: null
implemented: true
---

# Story: 001-intent-normalizer

## User Story

**As the** enforcement pipeline
**I want** to deterministically map each intercepted request into a canonical ExecutionEnvelope with a normalized action_class from the v0.1 Canonical Action Class Registry
**So that** policy evaluation operates on stable, transport-agnostic intent representations

## Acceptance Criteria

- [ ] **Given** a raw HTTP request matching a configured mapping rule, **When** the intent normalizer processes it, **Then** the resulting ExecutionEnvelope contains the correct canonical action_class from the v0.1 registry
- [ ] **Given** the v0.1 Canonical Action Class Registry, **When** the normalizer is initialized, **Then** all 15 registry action classes are supported in the mapping configuration
- [ ] **Given** a configurable mapping table with entries matching on (method, host, path_pattern, body_fields), **When** a request matches a rule, **Then** the most specific matching rule is selected deterministically
- [ ] **Given** the same semantic action arriving from different transports (e.g., HTTP POST vs future gRPC), **When** both are normalized, **Then** they produce the same action_class (cross-transport normalization)
- [ ] **Given** a successfully normalized request, **When** the ExecutionEnvelope is created, **Then** all five intent sub-fields are populated: action_class, resource, parameters, raw_transport, raw_action_ref
- [ ] **Given** an ambiguous raw execution surface that genuinely maps to system-level execution, **When** the normalizer processes it, **Then** system.execute is used only as a bounded high-risk fallback, not as a convenience class for unresolved mappings
- [ ] **Given** the mapping rules configuration, **When** the normalizer starts, **Then** rules are loaded from configuration (TOML or equivalent), not hardcoded in the binary
- [ ] **Given** a successfully created ExecutionEnvelope, **When** any component attempts to modify it, **Then** the modification is rejected at compile time (immutable after creation)

## Technical Notes

- The v0.1 Canonical Action Class Registry defines 15 action classes spanning domains such as file I/O, network, database, code execution, and system operations
- Mapping rules should be ordered by specificity; the normalizer must resolve conflicts deterministically (e.g., longest path prefix wins, or explicit priority field)
- The `parameters` field in the ExecutionEnvelope may contain a parameter hash rather than raw parameters to bound the size of the envelope
- `raw_transport` captures the original transport protocol (e.g., "http", "https") for audit and debugging
- `raw_action_ref` captures the original request signature (e.g., "POST /v1/chat/completions") for traceability
- ExecutionEnvelope immutability is enforced via Rust's ownership model: private fields with no `&mut` accessors, constructed via a builder that consumes itself
- Mapping table schema should support wildcard patterns in host and path_pattern fields (e.g., `*.openai.com`, `/v1/*/completions`)

## Dependencies

### Requires

- firma-core (intent 002): `ExecutionEnvelope` type definition, intent sub-field types

### Enables

- 002-unclassified-intent-denial (consumes normalizer output to decide on unmappable actions)
- 003-stage1-token-validation (receives normalized ExecutionEnvelope for token validation)
- 005-two-phase-pipeline-integration (normalizer is the entry point of the pipeline)

## Edge Cases

| Scenario | Expected Behavior |
| -------- | ----------------- |
| Request matches multiple mapping rules | Most specific rule wins (deterministic tie-breaking by specificity score or explicit priority) |
| Request matches no mapping rules and is a protected action | Delegated to story 002 (DENY: UNCLASSIFIED_INTENT) |
| Request matches no mapping rules and is not a protected action | Passthrough or default handling per configuration |
| Mapping configuration file is missing at startup | Fail-fast: sidecar refuses to start with clear error |
| Mapping configuration file is malformed | Fail-fast: sidecar refuses to start with parse error details |
| Request body is too large to parse for body_fields matching | Apply rules based on method/host/path only; log warning; body_fields rules skipped |
| Empty or null action_class in mapping rule | Rejected at config load time (validation) |
| Duplicate mapping rules with identical match criteria | Rejected at config load time (validation error) |

## Out of Scope

- Dynamic mapping rule updates at runtime (rules are loaded at startup; hot-reload is a post-V1 enhancement)
- Non-HTTP transport interception (future eBPF, gRPC interception layers define their own raw-to-canonical mapping)
- Defining the 15 action classes themselves (owned by the Canonical Action Class Registry specification)
- DENY logic for unmappable actions (owned by story 002-unclassified-intent-denial)
