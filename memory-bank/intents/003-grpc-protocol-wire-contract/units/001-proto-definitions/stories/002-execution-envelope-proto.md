---
story: 002-execution-envelope-proto
unit: 001-proto-definitions
intent: 003-grpc-protocol-wire-contract
priority: must
status: planned
created: 2026-03-27T09:00:00.000Z
---

# Story: ExecutionEnvelope and Shared Messages

## Description

Define the core protocol messages in `types.proto`. Extends the initial `execution_envelope.proto` work with additional messages needed by the system.

## Acceptance Criteria

- [ ] `ExecutionEnvelope` message defined as the core protocol unit (documented as such)
- [ ] `ExecutionIntent`, `ExecutionMetadata` sub-messages defined
- [ ] `CapabilityToken` message with format enum (PASETO_V4 / JWT_RS256)
- [ ] `PolicyBundle` message (version, policies, schema, ttl)
- [ ] `RevocationEvent` message (token_id, reason, timestamp)
- [ ] `EnforcementDecision` enum (ALLOW, DENY, ABORT)
- [ ] `ConnectorResponse` message
- [ ] Proto comments capture: ExecutionEnvelope is immutable once created, provenance is V1 placeholder

## Technical Notes

- Adapts initial `execution_envelope.proto` into `firma.v1` package
- Adds messages not in initial work: CapabilityToken, PolicyBundle, RevocationEvent, EnforcementDecision
- Uses `google.protobuf.Struct` for ExecutionIntent params (flexible key-value)
- Uses `google.protobuf.Timestamp` for typed timestamps
