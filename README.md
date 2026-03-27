# Firma OSS

Firma OSS is the open-source release of the Firma security architecture for AI agents. It provides L7 policy enforcement via a sidecar proxy pattern — every outbound call from an agent passes through the Firma Sidecar before reaching the external system.

## Architecture

```
                    ┌──────────────────────────────────────────────┐
                    │  Agent Host / Container                      │
                    │                                              │
                    │  ┌──────────┐  HTTP_PROXY   ┌─────────────┐ │
                    │  │ AI Agent │ ────────────── │   Sidecar   │ │
                    │  └──────────┘               │ (Gate)      │ │
                    │                             │             │ │
                    │                             │ ┌─────────┐ │ │
                    │                             │ │ Stage 1 │ │ │──── External
                    │                             │ │ crypto  │ │ │     System
                    │                             │ ├─────────┤ │ │
                    │                             │ │ Stage 2 │ │ │
                    │                             │ │ Cedar   │ │ │
                    │                             │ └─────────┘ │ │
                    │                             └──────┬──────┘ │
                    │                                    │ gRPC   │
                    │                             ┌──────┴──────┐ │
                    │                             │  Authority  │ │
                    │                             │ (pre-flight)│ │
                    │                             └─────────────┘ │
                    └──────────────────────────────────────────────┘
```

### Authority — Permission Perimeter

The Authority evaluates Cedar policies at issuance time and defines the **permission perimeter**: scope, budget, and expiry. The Gate (Sidecar) enforces within that perimeter but **cannot extend or override it**. The Authority is contacted only at pre-flight (capability issuance), never on the hot path.

### Gate (Sidecar) — Two-Stage Enforcement

Every outbound call passes through two enforcement stages, both fully local with no network calls:

- **Stage 1 — Capability Validation** (< 1ms): Token parse, signature verification, expiry check, revocation bloom filter. Rejects forged, tampered, expired, or revoked tokens.
- **Stage 2 — Constraint / Policy Enforcement (CEE)** (< 200us): Context build, Cedar policy evaluation, budget/scope/threshold checks. Deterministic: same context + same bundle = same decision.

### ExecutionEnvelope — Core Protocol Unit

The ExecutionEnvelope is the fundamental protocol unit flowing through the entire system. Every outbound call from an agent is represented as a distinct ExecutionEnvelope, evaluated independently by the Sidecar. Each request is evaluated, enforced, and audited as an ExecutionEnvelope. Treated as immutable once created.

### Connectors — Technical Constraints Only

Connectors translate the ExecutionEnvelope into target system protocols (HTTP, gRPC, DB). They apply **technical constraints only**: rate limits, schema validation, protocol translation. Business logic and authorization **must** remain in Cedar / Authority / Gate. A connector that becomes a second policy engine breaks auditability and system guarantees.

## Workspace Crates

| Crate | Type | Responsibility |
|-------|------|----------------|
| `firma-core` | Library | Shared types, capability tokens, Cedar wrapper, error types |
| `firma-proto` | Library | Protobuf/gRPC service definitions and generated code (wire contract) |
| `firma-sidecar` | Binary | HTTP proxy, two-stage enforcement pipeline, audit, credential injection |
| `firma-authority` | Binary | Mini Authority — Cedar policy loading, capability issuance, gRPC streams |

## Wire Contract (`firma-proto`)

The gRPC contract between Sidecar and Authority:

- **AuthorityService** — `IssueCapability` (unary), `WatchPolicyBundle` (server-stream), `WatchRevocations` (server-stream)
- **ExecutionEnvelope** — intent, capability token, metadata, provenance
- **CapabilityToken** — PASETO v4 (preferred) or JWT RS256
- **PolicyBundle** — Cedar policies distributed from Authority to Sidecar
- **EnforcementDecision** — ALLOW, DENY, ABORT

## License

Apache 2.0
