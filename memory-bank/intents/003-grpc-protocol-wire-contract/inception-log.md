---
intent: 003-grpc-protocol-wire-contract
phase: inception
created: 2026-03-27T09:00:00.000Z
---

# Inception Log: gRPC Protocol & Wire Contract

## Inception Complete

### Context

Initial proto work was proposed with:
- `execution_envelope.proto` at repo root (non-standard location)
- `firma_connector/` standalone crate outside the workspace
- README rewrite

Review identified the following requirements for the security model documentation:

1. **Stage 1 vs Stage 2**: Gate description must show the two-stage enforcement distinction
2. **Permission perimeter**: Authority defines the ceiling; Gate enforces within it but cannot extend
3. **Core protocol unit**: ExecutionEnvelope is the fundamental unit flowing through the system, not just a message
4. **Connector boundary rule**: Hard invariant — no business/policy logic in connectors

### Decisions

| Decision | Rationale |
|----------|-----------|
| Preserve initial ExecutionEnvelope message design | Accurate representation of component reference |
| Move proto to `crates/firma-proto/proto/firma/v1/` | Matches workspace structure and standard proto layout |
| Add AuthorityService RPCs | Core of intent 003, not covered by initial work |
| Defer connector code to intent 006 | Connector implementation belongs in firma-sidecar per intent plan |
| Remove `firma-core` dependency from `firma-proto` | Proto crate should not depend on core — the dependency goes the other way |
| Single unit decomposition | All proto work is tightly coupled |

### Additional Messages Added

- `CapabilityToken` — token format and claims
- `PolicyBundle` — Cedar policy distribution
- `RevocationEvent` — token invalidation
- `EnforcementDecision` enum — ALLOW/DENY/ABORT
- AuthorityService RPC request/response messages
