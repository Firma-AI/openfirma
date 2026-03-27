---
unit: 001-proto-definitions
intent: 003-grpc-protocol-wire-contract
phase: construction
status: complete
created: 2026-03-27T09:30:00.000Z
updated: 2026-03-27T09:30:00.000Z
---

# Construction Log: Proto Definitions

## Bolt 001 — Proto Files, Build Pipeline, Workspace Integration

### Input

- Initial `execution_envelope.proto` — adapted and extended
- Security model review (4 points) — all addressed
- Component reference sections 3.2–3.4, 4.2–4.4, 5, 7

### What Was Built

1. **`proto/firma/v1/types.proto`** — Shared message types:
   - `ExecutionEnvelope` (core protocol unit), `ExecutionIntent`, `ExecutionMetadata`
   - `CapabilityToken` with `TokenFormat` enum (PASETO_V4 / JWT_RS256)
   - `PolicyBundle`, `RevocationEvent`, `EnforcementDecision`, `ConnectorResponse`

2. **`proto/firma/v1/authority.proto`** — AuthorityService definition:
   - `IssueCapability` (unary) with request/response messages
   - `WatchPolicyBundle` (server-streaming) with `PolicyBundleUpdate`
   - `WatchRevocations` (server-streaming) reusing `RevocationEvent`

3. **`build.rs`** — tonic-build compilation of both proto files

4. **`Cargo.toml`** — Added prost 0.13, tonic 0.12, tonic-build 0.12. Removed firma-core dep.

5. **`lib.rs`** — Generated code re-exports with clippy allows for generated code

6. **`README.md`** — Rewritten to document the security model correctly

### Security Model Review Resolution

| # | Point | Resolution |
|---|-------|------------|
| 1 | Stage 1 vs Stage 2 distinction | README shows two-stage enforcement with descriptions and latency targets |
| 2 | Authority = permission perimeter | README states Gate enforces within but cannot extend the perimeter |
| 3 | ExecutionEnvelope = core protocol unit | README and proto comments emphasize it's the fundamental unit, not just a message |
| 4 | Connector boundary rule | README states hard invariant: no business/policy logic in connectors |

### Structural Fixes Applied

- Proto message definitions preserved and improved in `types.proto`
- Connector crate deferred to intent 006 (connector belongs in sidecar)
- Build artifacts excluded
- Proto file moved from repo root to `crates/firma-proto/proto/firma/v1/`

### Validation

- `cargo build --workspace` — PASS
- `cargo clippy --workspace -- -D warnings` — PASS
- `cargo fmt --check` — PASS
- `cargo test --workspace` — PASS
- `make check` — PASS
