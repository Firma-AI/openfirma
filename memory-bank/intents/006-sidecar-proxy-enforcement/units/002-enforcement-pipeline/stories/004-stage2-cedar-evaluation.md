---
id: 004-stage2-cedar-evaluation
unit: 002-enforcement-pipeline
intent: 006-sidecar-proxy-enforcement
status: complete
priority: must
created: 2026-04-05T12:00:00.000Z
assigned_bolt: null
implemented: true
---

# Story: 004-stage2-cedar-evaluation

## User Story

**As the** enforcement pipeline
**I want** Stage 2 to build a Cedar evaluation context and evaluate policies deterministically
**So that** authorization decisions are consistent, auditable, and based on the current policy bundle

## Acceptance Criteria

- [ ] **Given** a verified ExecutionEnvelope from Stage 1, **When** the Context Builder runs, **Then** the Cedar context includes base attributes: action_class, resource, agent_id, session_id, timestamp
- [ ] **Given** Sidecar-managed local state, **When** the Context Builder runs, **Then** the Cedar context includes: budget_remaining (generic budget tracking), request_count (session-scoped counter), action_count_window (configurable sliding window counter per action class)
- [ ] **Given** operator-defined custom attributes in the Sidecar configuration, **When** the Context Builder runs, **Then** trusted config-sourced attributes and untrusted agent-supplied metadata attributes are included in the context with appropriate trust labels
- [ ] **Given** a .cedarschema file defining the entity schema, **When** the context is built, **Then** the attribute schema is driven by the .cedarschema definition, not hardcoded in the Sidecar binary
- [ ] **Given** the same Cedar context and the same policy bundle, **When** evaluation runs multiple times, **Then** the result is identical every time (deterministic evaluation)
- [ ] **Given** a verified capability token with an allowed action set, **When** Stage 2 runs the scope check, **Then** it validates that the current action_class is within the token's allowed action set; if not, DENY with SCOPE_VIOLATION
- [ ] **Given** any Stage 2 evaluation, **When** measured under load, **Then** the p95 latency is less than 200 microseconds
- [ ] **Given** a Cedar evaluation result of ALLOW, **When** Stage 2 completes, **Then** the request proceeds to credential injection and the connector
- [ ] **Given** a Cedar evaluation result of DENY, **When** Stage 2 completes, **Then** a structured DENY response with the appropriate reason code is returned
- [ ] **Given** the Context Builder, **When** it populates context attributes, **Then** it does not read LLM scratchpads, reasoning traces, prompt windows, or orchestration memory

## Technical Notes

- Cedar context is constructed as a Cedar `Context` object conforming to the entity schema defined in `.cedarschema`
- Base attributes are derived directly from the ExecutionEnvelope:
  - `action_class`: canonical action class string
  - `resource`: normalized resource identifier
  - `agent_id`: from the verified capability token claims
  - `session_id`: from the verified capability token claims
  - `timestamp`: current wall-clock time (UTC)
- Sidecar-managed attributes are computed locally by the Sidecar:
  - `budget_remaining`: tracks a generic budget counter (decremented per action, configurable initial value)
  - `request_count`: monotonic counter per session
  - `action_count_window`: sliding window counter tracking how many times a specific action_class has been invoked in a configurable time window
- Operator-defined custom attributes come in two trust categories:
  - Trusted: sourced from Sidecar configuration (e.g., deployment environment, tenant ID)
  - Untrusted: sourced from agent-supplied metadata headers (must be explicitly declared in config to be admitted)
- The scope check is a pre-Cedar gate: if the action_class is not in the token's `actions` set, DENY with SCOPE_VIOLATION before Cedar evaluation runs
- Cedar evaluation uses the `cedar-policy` crate's `Authorizer` with the current in-memory policy set from unit 003
- Policy bundle versioning: the bundle version is recorded for audit but does not affect evaluation logic
- The Context Builder is a pure function: (ExecutionEnvelope, SidecarState, Config) -> CedarContext

## Dependencies

### Requires

- 001-intent-normalizer (provides normalized ExecutionEnvelope with action_class and resource)
- 003-stage1-token-validation (provides verified CapabilityClaims with agent_id, session_id, actions)
- 003-policy-revocation (unit 003): provides current Cedar policy bundle for evaluation
- firma-core (intent 002): `PolicyEvaluator` trait, `Decision` type
- cedar-policy crate: `Authorizer`, `PolicySet`, `Context`, `Request` types

### Enables

- 005-two-phase-pipeline-integration (Stage 2 is the second phase of the two-phase pipeline)
- 005-connector-credentials (unit 005): ALLOW decision triggers credential injection
- 006-audit-observability (unit 006): context_hash included in audit events

## Edge Cases

| Scenario | Expected Behavior |
| -------- | ----------------- |
| Action is not in the token's allowed action set | DENY: SCOPE_VIOLATION before Cedar evaluation runs |
| Token has a wildcard action set (all actions allowed) | Scope check passes; Cedar policies still evaluated |
| Cedar policy set is empty (no policies loaded) | Cedar default-deny: no matching permit policy means DENY: POLICY_DENIED |
| Cedar evaluation returns an error (malformed policy) | DENY: internal error; should not happen if bundle is validated at load time |
| budget_remaining reaches zero | Cedar policy can reference this attribute; DENY: BUDGET_EXCEEDED is policy-driven |
| action_count_window exceeds configured threshold | Cedar policy references this attribute; rate limiting is policy-driven |
| Agent-supplied metadata contains unexpected keys | Only keys declared in config are admitted to context; undeclared keys are dropped silently |
| Agent-supplied metadata contains excessively large values | Configurable max size per attribute value; oversized values are truncated or dropped |
| .cedarschema is missing at startup | Sidecar fails to start (fail-fast) |
| .cedarschema and policy files are inconsistent | Cedar validation catches schema-policy mismatches at bundle load time |
| Concurrent Stage 2 evaluations share the same policy set | Policy set is immutable (Arc-wrapped); concurrent reads are safe |

## Out of Scope

- Dynamic risk scoring engine (V1 uses static risk_score attribute only)
- Trust graph evaluation (post-V1)
- Escalation / human-in-the-loop outcomes (V1 is binary ALLOW/DENY only)
- Policy bundle loading, caching, or hot-reload (owned by unit 003-policy-revocation)
- Budget decrement logic after ALLOW (owned by the connector/audit path, not the evaluation path)
- Defining Cedar policies themselves (operator responsibility; the Sidecar evaluates them)
