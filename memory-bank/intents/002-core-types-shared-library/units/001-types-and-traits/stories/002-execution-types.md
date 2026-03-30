---
id: 002-execution-types
unit: 001-types-and-traits
intent: 002-core-types-shared-library
status: complete
priority: must
created: 2026-03-26T14:10:00.000Z
assigned_bolt: null
implemented: true
---

# Story: 002-execution-types

## User Story

**As a** Sidecar developer
**I want** well-defined Execution Envelope and Execution Context types
**So that** I can build, inspect, and evaluate every outbound agent call through a consistent structure

## Acceptance Criteria

- [ ] **Given** the `ExecutionEnvelope` struct, **When** I construct it with intent, capability, and metadata fields, **Then** it compiles and all fields are accessible
- [ ] **Given** the `ExecutionIntent` struct with typed action params (HttpParams, DbQueryParams, ToolUseParams via enum), **When** I construct any variant, **Then** it compiles and the action-specific fields are accessible
- [ ] **Given** the `ExecutionContext` struct, **When** I construct it with agent_id, action, resource, and session metadata, **Then** it compiles and all fields are accessible
- [ ] **Given** an `ExecutionEnvelope`, **When** I build an `ExecutionContext` from its fields, **Then** all relevant fields map correctly

## Technical Notes

- `ExecutionEnvelope` fields (aligned with PR #5 review feedback):
  - `intent`: `ExecutionIntent` with typed action params via enum (HttpParams, DbQueryParams, ToolUseParams) — NOT a generic HashMap/Struct (PR #5: injection risk)
  - `capability`: the raw signed token string (not parsed claims — parsing happens in Stage 1)
  - `metadata`: struct with session_id, agent_id, timestamp, trace_id — NO budget_consumed (PR #5: unclear computation, deferred), NO risk_score (PR #5: deferred until anomaly detection exists)
  - NO provenance field (PR #5: confusing, V1 placeholder with no implementation — add back when designed)
- `ExecutionContext` is what Stage 2 (Cedar eval) reads — built from envelope fields plus Sidecar local state
- Consider a `From<&ExecutionEnvelope>` or builder for `ExecutionContext`
- Sub-structs (`ExecutionIntent`, `RequestMetadata`, `HttpParams`, `DbQueryParams`, `ToolUseParams`) should be separate named types

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
| Action type not covered by HttpParams/DbQueryParams/ToolUseParams | Use a generic/extensible variant or return error — design during construction |

## Out of Scope

- Building an ExecutionEnvelope from an HTTP request (Sidecar Interceptor, intent 006)
- Cedar entity conversion from ExecutionContext (intents 005/006)
