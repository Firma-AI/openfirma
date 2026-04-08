---
unit: 002-enforcement-pipeline
intent: 006-sidecar-proxy-enforcement
phase: inception
status: complete
created: 2026-04-05T12:00:00.000Z
updated: 2026-04-05T12:00:00.000Z
---

# Unit Brief: Enforcement Pipeline

## Purpose

Implement the core two-phase enforcement engine that evaluates every intercepted request: Stage 1 capability token validation (PASETO v4 parse, verify, expiry, revocation) and Stage 2 Cedar policy evaluation (context building, policy evaluation, scope check). Also includes the intent normalizer that maps raw requests to canonical ExecutionEnvelopes.

## Scope

### In Scope

- Intent normalizer with configurable mapping table
- v0.1 Canonical Action Class Registry (all 15 action classes)
- ExecutionEnvelope builder with all five intent sub-fields
- `DENY: UNCLASSIFIED_INTENT` for unmappable protected actions
- `system.execute` bounded fallback for ambiguous raw execution surfaces
- Stage 1: PASETO v4 token parsing via firma-core `TokenVerifier`
- Stage 1: Cryptographic signature verification, expiry check, revocation check
- Stage 1: Structured deny codes (`TOKEN_INVALID`, `TOKEN_EXPIRED`, `TOKEN_REVOKED`)
- Stage 2: Cedar context building from envelope + Sidecar state + runtime signals
- Stage 2: Base attributes (action_class, resource, agent_id, session_id, timestamp)
- Stage 2: Sidecar-managed attributes (budget_remaining, request_count, action_count_window)
- Stage 2: Operator-defined custom attributes (untrusted agent metadata, trusted config)
- Stage 2: Cedar policy evaluation (deterministic, same context + bundle = same result)
- Stage 2: Scope check (action within capability token's allowed action set)
- Integrated two-phase pipeline: Stage 1 → Stage 2, short-circuit on failure

### Out of Scope

- Policy bundle loading/caching (owned by 003-policy-revocation)
- Revocation data sourcing (owned by 003-policy-revocation; this unit reads the cache)
- LLM response-path evaluation (owned by 004-llm-response-parser; reuses this pipeline)
- HTTP proxy transport (owned by 001-proxy-core)

---

## Assigned Requirements

| FR | Requirement | Priority |
|----|-------------|----------|
| FR-2 | Intent Normalizer / Envelope Builder | Must |
| FR-3 | Stage 1 — Capability Validation | Must |
| FR-4 | Stage 2 — Constraint Enforcement Engine (CEE) | Must |

---

## Domain Concepts

### Key Entities

| Entity | Description | Attributes |
|--------|-------------|------------|
| ExecutionEnvelope | Normalized representation of an intercepted request | action_class, resource, parameters, raw_transport, raw_action_ref |
| MappingRule | Maps raw request patterns to canonical action classes | method, host, path_pattern, body_fields → action_class |
| CedarContext | Context object for Cedar policy evaluation | base attrs, sidecar attrs, custom attrs |
| Decision | Binary enforcement outcome | ALLOW or DENY with structured reason |
| DenyReason | Structured denial reason code | TOKEN_INVALID, TOKEN_EXPIRED, TOKEN_REVOKED, POLICY_DENIED, SCOPE_VIOLATION, etc. |

### Key Operations

| Operation | Description | Inputs | Outputs |
|-----------|-------------|--------|---------|
| normalize_intent | Map raw request to canonical ExecutionEnvelope | HTTP method, host, path, body | ExecutionEnvelope |
| validate_token | Stage 1: parse, verify, check expiry/revocation | Capability token, Authority pubkey, revocation cache | Pass or DENY |
| build_context | Construct Cedar evaluation context | ExecutionEnvelope, Sidecar state, runtime signals | CedarContext |
| evaluate_policy | Stage 2: Cedar policy evaluation | CedarContext, policy bundle | ALLOW or DENY |
| enforce | Run full two-phase pipeline | Raw request + token | Decision |

---

## Story Summary

| Metric | Count |
|--------|-------|
| Total Stories | 5 |
| Must Have | 5 |
| Should Have | 0 |
| Could Have | 0 |

### Stories

| Story ID | Title | Priority | Status |
|----------|-------|----------|--------|
| 001-intent-normalizer | Mapping table + action class registry → ExecutionEnvelope | Must | Planned |
| 002-unclassified-intent-denial | DENY: UNCLASSIFIED_INTENT for unmappable actions | Must | Planned |
| 003-stage1-token-validation | PASETO v4 parse, verify, expiry, revocation | Must | Planned |
| 004-stage2-cedar-evaluation | Cedar context build + policy eval + scope check | Must | Planned |
| 005-two-phase-pipeline-integration | Wire Stage 1 → Stage 2, structured deny on failure | Must | Planned |

---

## Dependencies

### Depends On

| Unit | Reason |
|------|--------|
| firma-core (intent 002) | `TokenVerifier`, `PolicyEvaluator` traits, `CapabilityClaims`, `ExecutionEnvelope`, `Decision` types |
| 003-policy-revocation | Reads revocation cache for Stage 1, reads policy bundle for Stage 2 |

### Depended By

| Unit | Reason |
|------|--------|
| 004-llm-response-parser | Evaluates extracted tool calls through the enforcement pipeline |
| 001-proxy-core | Calls enforcement pipeline from Pingora lifecycle hooks |

### External Dependencies

| System | Purpose | Risk |
|--------|---------|------|
| cedar-policy crate | Policy evaluation engine | Low — mature, deterministic |
| firma-core | Traits and types | Low — intent 002 complete |

---

## Technical Context

### Suggested Technology

- firma-core types and traits
- cedar-policy crate for Stage 2 evaluation
- Configurable mapping rules (loaded from TOML/config)

### Integration Points

| Integration | Type | Protocol |
|-------------|------|----------|
| firma-core | Library | Rust traits |
| Policy bundle (from 003) | Internal | In-memory policy set |
| Revocation cache (from 003) | Internal | In-memory bloom filter + LRU |

---

## Constraints

- Stage 1 latency < 1ms p95
- Stage 2 latency < 200us p95
- Cedar context schema defined by `.cedarschema`, not hardcoded
- Mapping rules loaded from configuration, not hardcoded
- Normalized ExecutionEnvelope is immutable after creation
- Context Builder must not read LLM scratchpads or reasoning traces
- Deterministic: same context + same bundle = same result

---

## Success Criteria

### Functional

- [ ] All 15 v0.1 registry action classes supported
- [ ] DENY: UNCLASSIFIED_INTENT for unmappable protected actions
- [ ] PASETO v4 tokens parsed and verified
- [ ] Expired/revoked/forged tokens rejected with correct reason codes
- [ ] Cedar context includes base, sidecar-managed, and custom attributes
- [ ] Scope check validates action within token's allowed set
- [ ] Two-phase pipeline short-circuits on Stage 1 failure

### Non-Functional

- [ ] Stage 1 < 1ms p95
- [ ] Stage 2 < 200us p95
- [ ] Deterministic evaluation

### Quality

- [ ] Cedar context schema-contract tests
- [ ] Every error path ends in DENY (fail-closed discipline)
- [ ] Comprehensive mapping rule tests for all 15 action classes

---

## Bolt Suggestions

| Bolt | Type | Stories | Objective |
|------|------|---------|-----------|
| 008-enforcement-pipeline | DDD | 001, 002, 003, 004, 005 | Full two-phase enforcement pipeline |

---

## Notes

- Cedar context schema is the highest-risk area — silent policy non-match is invisible and dangerous
- Every error path must be tested to confirm it ends in DENY, not panic or pass-through
- The enforcement pipeline is reused by both request-path (proxy-core) and response-path (llm-response-parser) evaluation
