---
story: 001-authority-service-proto
unit: 001-proto-definitions
intent: 003-grpc-protocol-wire-contract
priority: must
status: complete
created: 2026-03-27T09:00:00.000Z
---

# Story: AuthorityService RPC Definitions

## Description

Define the `AuthorityService` gRPC service in `authority.proto` with three RPCs that form the control-plane contract between sidecar and authority.

## Acceptance Criteria

- [x] `IssueCapability` unary RPC defined with request/response messages
- [x] `WatchPolicyBundle` server-streaming RPC defined
- [x] `WatchRevocations` server-streaming RPC defined
- [x] Proto comments document the permission perimeter model: Authority defines the ceiling, Gate enforces within it
- [x] Proto comments document that Authority is contacted only at pre-flight, never on the hot path

## Technical Notes

- RPCs per component reference sections 3.2–3.4
- `IssueCapability`: receives agent identity + requested scope, returns signed token or denial reason
- `WatchPolicyBundle`: streams current bundle on connect, then pushes updates
- `WatchRevocations`: streams revocation events for bloom filter/LRU cache population
