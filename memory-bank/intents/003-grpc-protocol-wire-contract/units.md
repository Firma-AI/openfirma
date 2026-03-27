---
intent: 003-grpc-protocol-wire-contract
phase: inception
status: units-defined
updated: 2026-03-27T09:00:00Z
---

# Unit Decomposition: 003-grpc-protocol-wire-contract

## Units

| Unit | Purpose | Stories | Bolt Type |
|------|---------|---------|-----------|
| 001-proto-definitions | Proto files, build pipeline, generated code, workspace integration | 4 | simple-construction-bolt |

## Requirement-to-Unit Mapping

- **FR-1**: AuthorityService Proto Definition → `001-proto-definitions`
- **FR-2**: ExecutionEnvelope Message → `001-proto-definitions`
- **FR-3**: CapabilityToken Message → `001-proto-definitions`
- **FR-4**: RPC Request/Response Messages → `001-proto-definitions`
- **FR-5**: Supporting Messages → `001-proto-definitions`
- **FR-6**: prost/tonic Build Pipeline → `001-proto-definitions`
- **FR-7**: Workspace Integration → `001-proto-definitions`

## Rationale

Single unit because all proto definitions, the build pipeline, and workspace integration are tightly coupled — you can't compile the service definition without the message types, and the build pipeline must compile everything together. No domain logic to decompose.
