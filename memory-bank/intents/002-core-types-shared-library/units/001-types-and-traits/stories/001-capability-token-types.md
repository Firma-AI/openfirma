---
id: 001-capability-token-types
unit: 001-types-and-traits
intent: 002-core-types-shared-library
status: draft
priority: must
created: 2026-03-26T14:10:00Z
assigned_bolt: null
implemented: false
---

# Story: 001-capability-token-types

## User Story

**As a** Firma component developer (Sidecar or Authority)
**I want** well-defined capability token types with all required fields
**So that** I can issue, sign, verify, and inspect capability tokens with a consistent structure

## Acceptance Criteria

- [ ] **Given** the `CapabilityClaims` struct, **When** I construct it with all fields (token_id, agent_id, session_id, actions, resources, issued_at, expires_at, context_hash), **Then** it compiles and all fields are accessible
- [ ] **Given** a `CapabilityClaims` instance, **When** I serialize it to JSON, **Then** the output contains all fields with correct types
- [ ] **Given** the `TokenState` enum, **When** I use any variant (Issued, Active, InUse, Expired, Revoked, Aborted), **Then** it compiles and can be matched exhaustively
- [ ] **Given** a `CapabilityClaims` struct, **When** I derive Debug and Clone, **Then** both work correctly

## Technical Notes

- `CapabilityClaims` fields based on component reference Section 3.5 and Section 5
- `actions` is a `Vec<String>` or `HashSet<String>` representing the action set
- `resources` is a `Vec<String>` representing the resource scope
- `issued_at` and `expires_at` use `chrono::DateTime<Utc>`
- `context_hash` is a `String` (hex-encoded SHA-256 of the Cedar context at issuance)
- All fields derive `Serialize`, `Deserialize` via serde

## Dependencies

### Requires

- None (first story)

### Enables

- 002-execution-types (ExecutionEnvelope references capability token)
- 004-trait-interfaces (TokenSigner/TokenVerifier use CapabilityClaims)

## Edge Cases

| Scenario | Expected Behavior |
| -------- | ----------------- |
| Empty actions set | Valid — represents a token with no actions (Authority decides scope) |
| expires_at in the past | Valid at construction time — validation happens in TokenVerifier |
| Very long token_id | Accepted — no length limit at type level |

## Out of Scope

- Token validation logic (that's in TokenVerifier trait implementation)
- PASETO/JWT serialization (that's in Unit 002)
