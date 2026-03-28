---
id: 002-execution-types
unit: 001-types-and-traits
intent: 002-core-types-shared-library
status: draft
priority: must
created: 2026-03-26T14:10:00Z
assigned_bolt: null
implemented: false
---

# Story: 002-execution-types

## User Story

**As a** Sidecar developer
**I want** well-defined Execution Envelope and Execution Context types
**So that** I can build, inspect, and evaluate every outbound agent call through a consistent structure

## Acceptance Criteria

- [ ] **Given** the `ExecutionEnvelope` struct, **When** I construct it with intent, capability, metadata, and provenance fields, **Then** it compiles and all fields are accessible
- [ ] **Given** an `ExecutionEnvelope`, **When** provenance is not set, **Then** it is `None` (Option type)
- [ ] **Given** the `ExecutionContext` struct, **When** I construct it with agent_id, action, resource, budget_remaining, risk_score, and session metadata, **Then** it compiles and all fields are accessible
- [ ] **Given** an `ExecutionEnvelope`, **When** I build an `ExecutionContext` from its fields, **Then** all relevant fields map correctly

## Technical Notes

- `ExecutionEnvelope` fields per component reference Section 4.2:
  - `intent`: struct with action_type, target_resource, parameters
  - `capability`: the raw signed token string (not parsed claims — parsing happens in Stage 1)
  - `metadata`: struct with session_id, agent_id, timestamp, trace_id, budget_consumed
  - `provenance`: `Option<String>` — reserved, nullable in V1
- `ExecutionContext` is what Stage 2 (Cedar eval) reads — built from envelope fields plus Sidecar local state
- Consider a `From<&ExecutionEnvelope>` or builder for `ExecutionContext`
- Sub-structs (`Intent`, `RequestMetadata`) should be separate named types, not tuples

## Dependencies

### Requires

- 001-capability-token-types (capability field references token)

### Enables

- 003-decision-and-errors (Decision is the output of evaluating a context)
- 004-trait-interfaces (PolicyEvaluator takes ExecutionContext)

## Edge Cases

| Scenario | Expected Behavior |
| -------- | ----------------- |
| Missing trace_id in metadata | Valid — use `Option<String>` for trace_id |
| budget_consumed is negative | Allowed at type level — validation is caller's responsibility |
| Very large parameters map | Accepted — no size limit at type level |

## Out of Scope

- Building an ExecutionEnvelope from an HTTP request (Sidecar Interceptor, intent 006)
- Cedar entity conversion from ExecutionContext (intents 005/006)
