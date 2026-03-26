# API Conventions

## Overview

Firma OSS exposes two API surfaces: gRPC for control-plane communication between Sidecar and Authority, and HTTP proxy responses from the Sidecar to agents. Protobuf is the source of truth for gRPC contracts.

## API Style

- **Sidecar ↔ Authority**: gRPC (Tonic) with Protobuf
- **Agent ↔ Sidecar**: HTTP proxy (transparent, not a Firma-specific API)
- **Audit emission**: Structured JSON lines to stdout/file (not a network API in V1)

Why gRPC: Strong typing via Protobuf, streaming support, code generation for multiple languages, natural fit for Capability Library SDKs.

## Protobuf Conventions

### Package Naming

```protobuf
package firma.authority.v1;
package firma.sidecar.v1;
package firma.audit.v1;
```

### File Organization

Proto files live under `crates/firma-proto/proto/` following the package hierarchy (`firma/{domain}/v1/*.proto`). Shared types live under `firma/common/v1/`. Each service domain gets its own subdirectory.

### Naming Rules

- **Services**: PascalCase, suffixed with `Service` (e.g., `AuthorityService`)
- **RPCs**: PascalCase, verb-first (e.g., `IssueCapability`, `WatchPolicyBundle`)
- **Messages**: PascalCase (e.g., `CapabilityToken`, `ExecutionEnvelope`)
- **Fields**: snake_case (e.g., `agent_id`, `token_id`, `bundle_version`)
- **Enums**: PascalCase with UPPER_SNAKE_CASE values, prefixed with enum name (e.g., `DECISION_ALLOW`, `DECISION_DENY`)

## Versioning

**URL-path versioning** in Protobuf package names: `firma.authority.v1`

- V1 is the initial stable contract
- Breaking changes require a new version (`v2`)
- Non-breaking additions (new fields, new RPCs) are added to the current version
- Protobuf field numbering must never be reused after deletion

## Pagination Strategy

Not applicable for V1. gRPC streaming handles continuous data flow (policy bundles, revocations). No REST endpoints with paginated collections.
