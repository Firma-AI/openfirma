---
id: 002-unclassified-intent-denial
unit: 002-enforcement-pipeline
intent: 006-sidecar-proxy-enforcement
status: complete
priority: must
created: 2026-04-05T12:00:00.000Z
assigned_bolt: null
implemented: true
---

# Story: 002-unclassified-intent-denial

## User Story

**As the** enforcement pipeline
**I want** to deny protected actions that cannot be deterministically mapped to a canonical action class
**So that** unknown or ambiguous actions fail closed rather than passing through

## Acceptance Criteria

- [ ] **Given** a protected action that cannot be deterministically mapped to any canonical action class, **When** the intent normalizer attempts classification, **Then** a DENY with reason code UNCLASSIFIED_INTENT is returned
- [ ] **Given** the system.execute action class, **When** an ambiguous action is encountered, **Then** system.execute is reserved exclusively for genuinely ambiguous raw execution surfaces (e.g., arbitrary shell commands), not used as a convenience fallback for mapping failures
- [ ] **Given** a protected action that partially matches multiple mapping rules without a deterministic winner, **When** classification is attempted, **Then** the action is denied as UNCLASSIFIED_INTENT rather than guessing
- [ ] **Given** a DENY: UNCLASSIFIED_INTENT decision, **When** it is returned, **Then** the denial includes the raw_transport, raw_action_ref, and a human-readable detail explaining why the action could not be classified
- [ ] **Given** a non-protected action (e.g., health check, OPTIONS preflight) that does not match any mapping rule, **When** the normalizer processes it, **Then** it is handled per configuration (passthrough or default policy), not denied as UNCLASSIFIED_INTENT

## Technical Notes

- The distinction between "genuinely ambiguous raw execution surface" (maps to system.execute) and "protected action that cannot be mapped" (DENY: UNCLASSIFIED_INTENT) is critical for fail-closed discipline
- system.execute is a valid action class for raw command execution (e.g., `POST /exec` with a shell command body) where the intent genuinely is arbitrary execution; the key invariant is that it must not be used as a catch-all bucket
- The list of "protected actions" vs "non-protected actions" should be configurable; by default, all actions routed through the enforcement pipeline are considered protected
- UNCLASSIFIED_INTENT is one of the reason codes defined in the domain design decisions doc and must be included in HTTP 403 denial responses (FR-11)
- Audit events must be emitted for UNCLASSIFIED_INTENT denials (same as all other denials per FR-10)

## Dependencies

### Requires

- 001-intent-normalizer (provides the mapping table and classification logic that determines when an action is unmappable)
- firma-core (intent 002): `Decision` type, deny reason codes

### Enables

- 005-two-phase-pipeline-integration (UNCLASSIFIED_INTENT is a pre-Stage-1 denial that short-circuits the pipeline)

## Edge Cases

| Scenario | Expected Behavior |
| -------- | ----------------- |
| New API endpoint not yet added to mapping rules | DENY: UNCLASSIFIED_INTENT (fail-closed) |
| Mapping rule exists but with an unrecognized action_class not in the v0.1 registry | Rejected at config load time; if somehow encountered at runtime, DENY: UNCLASSIFIED_INTENT |
| Request to a host not covered by any mapping rule | DENY: UNCLASSIFIED_INTENT if the host is in the protected scope; passthrough if not |
| Ambiguous body_fields match (two rules match on different body fields) | DENY: UNCLASSIFIED_INTENT (no guessing) |
| system.execute mapped legitimately via a specific mapping rule | ALLOW classification as system.execute (this is the correct use of the fallback) |
| system.execute used because no other rule matched | DENY: UNCLASSIFIED_INTENT (system.execute must not be a convenience fallback) |
| Extremely high rate of UNCLASSIFIED_INTENT denials | Log at WARN level; emit metric for operator alerting; no automatic remediation |

## Out of Scope

- Automatic learning or suggestion of new mapping rules based on denied traffic patterns
- Operator notification or alerting pipelines for UNCLASSIFIED_INTENT spikes (observability is in unit 006)
- Defining the protected vs non-protected action boundary beyond configuration (no dynamic discovery)
