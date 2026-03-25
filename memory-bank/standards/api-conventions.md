# API Conventions

## Overview

Firma OSS exposes two API surfaces: gRPC control-plane contracts between Sidecar and Authority, and structured HTTP responses from the Sidecar proxy to agents. Protobuf is the source of truth for the gRPC control plane; proxy denial responses are a separate JSON-over-HTTP contract.

## API Style

**gRPC with Protobuf** for Sidecar ↔ Authority control-plane communication

- Sidecar ↔ Authority: gRPC (Tonic)
- Agent ↔ Sidecar: HTTP proxy (transparent, not a Firma-specific API)
- Audit emission in OSS V1: structured JSON lines to stdout/file (not a network API)

Why gRPC: Strong typing via Protobuf, streaming support (WatchPolicyBundle, WatchRevocations), code generation for multiple languages, natural fit for the Capability Library SDKs.

## Protobuf Conventions

### Package Naming

```protobuf
package firma.authority.v1;
package firma.sidecar.v1;
package firma.audit.v1;
```

### File Organization

```text
crates/firma-proto/proto/
├── firma/
│   ├── authority/
│   │   └── v1/
│   │       └── authority.proto      # Authority service definition
│   ├── sidecar/
│   │   └── v1/
│   │       └── sidecar.proto        # Sidecar session management
│   ├── audit/
│   │   └── v1/
│   │       └── audit.proto          # Audit event schema
│   └── common/
│       └── v1/
│           ├── envelope.proto       # Execution Envelope
│           ├── capability.proto     # Capability token schema
│           └── types.proto          # Shared types (Decision, ReasonCode, etc.)
```

### Naming Rules

- **Services**: PascalCase, suffixed with `Service` (e.g., `AuthorityService`)
- **RPCs**: PascalCase, verb-first (e.g., `IssueCapability`, `WatchPolicyBundle`)
- **Messages**: PascalCase (e.g., `CapabilityToken`, `ExecutionEnvelope`)
- **Fields**: snake_case (e.g., `agent_id`, `token_id`, `bundle_version`)
- **Enums**: PascalCase with UPPER_SNAKE_CASE values, prefixed with enum name (e.g., `DECISION_ALLOW`, `DECISION_DENY`)

## gRPC Service Definitions

### AuthorityService

```protobuf
service AuthorityService {
  // Pre-flight: Issue a capability token for an agent session
  rpc IssueCapability(IssueCapabilityRequest) returns (IssueCapabilityResponse);

  // Server-streaming: Push policy bundle updates to Sidecar
  rpc WatchPolicyBundle(WatchPolicyBundleRequest) returns (stream PolicyBundleUpdate);

  // Server-streaming: Push revocation events to Sidecar
  rpc WatchRevocations(WatchRevocationsRequest) returns (stream RevocationEvent);
}
```

### RPC Patterns

| Pattern | Used For | Example |
|---------|----------|---------|
| Unary | One-shot requests | `IssueCapability` |
| Server-streaming | Continuous push from Authority | `WatchPolicyBundle`, `WatchRevocations` |
| Client-streaming | Not used in V1 | — |
| Bidirectional | Not used in V1 | — |

### Authority Authentication

All Authority RPCs require an authenticated caller. OSS V1 does not standardize a single bootstrap authentication mechanism in the wire contract yet, but anonymous `IssueCapability` calls are forbidden.

This applies both to capability issuance and to background streaming RPCs such as `WatchPolicyBundle` and `WatchRevocations`.

## Versioning

**URL-path versioning** in Protobuf package names: `firma.authority.v1`

- V1 is the initial stable contract
- Breaking changes require a new version (`v2`)
- Non-breaking additions (new fields, new RPCs) are added to the current version
- Protobuf field numbering must never be reused after deletion

## Response Format

### gRPC Responses

Standard gRPC status codes + Firma-specific detail messages:

| Scenario | gRPC Status | Detail |
|----------|-------------|--------|
| Capability issued | OK | `IssueCapabilityResponse` with token |
| Caller unauthenticated | UNAUTHENTICATED | No capability issued; caller must authenticate first |
| Issuance denied by policy | PERMISSION_DENIED | Reason code + denied actions |
| Authority unavailable | UNAVAILABLE | Retry with backoff |
| Invalid request | INVALID_ARGUMENT | Field-level validation errors |
| Internal error | INTERNAL | Opaque error, logged server-side |

### HTTP Proxy Responses (Sidecar → Agent)

The Sidecar is a transparent HTTP proxy. On enforcement denial, it returns structured HTTP responses:

| Scenario | HTTP Status | Body Format |
|----------|-------------|-------------|
| ALLOW | Original upstream response | Passthrough (unchanged) |
| DENY (Stage 1) | 403 Forbidden | `{"firma_decision": "DENY", "reason": "TOKEN_EXPIRED", "detail": "..."}` |
| DENY (Stage 2) | 403 Forbidden | `{"firma_decision": "DENY", "reason": "POLICY_DENIED", "detail": "...", "action": "...", "resource": "..."}` |
| DENY (malformed) | 400 Bad Request | `{"firma_decision": "DENY", "reason": "MALFORMED_REQUEST", "detail": "..."}` |
| ABORT | 503 Service Unavailable | `{"firma_decision": "ABORT", "reason": "...", "detail": "..."}` |
| Credential injection failed | 502 Bad Gateway | `{"firma_decision": "DENY", "reason": "CREDENTIAL_INJECTION_FAILED"}` |

`AUTHORITY_UNAVAILABLE` is a pre-flight issuance failure, not a normal hot-path proxy denial. If capability issuance fails before a proxied request is sent, the initiating component surfaces that error outside the table above.

### LLM Response-Path Rewriting

When the Sidecar denies a tool call detected in an LLM response:

- Denied `function_call` is stripped from the response
- A `function_call_output` with `FIRMA_DENY` marker is injected
- Agent sees a normal-looking response (no Firma-specific handling needed)
- LLM self-corrects on the next turn

## Error Response Format

All Firma error responses follow a consistent JSON structure:

```json
{
  "firma_decision": "DENY | ABORT",
  "reason": "REASON_CODE",
  "detail": "Human-readable explanation",
  "request_id": "uuid-v7",
  "timestamp": "2026-03-25T12:00:00.000Z"
}
```

### Reason Codes

| Code | Source | Meaning |
|------|--------|---------|
| `TOKEN_INVALID` | Stage 1 | Token parse or signature verification failed |
| `TOKEN_EXPIRED` | Stage 1 | Token TTL elapsed |
| `TOKEN_REVOKED` | Stage 1 | Token found in revocation cache |
| `POLICY_DENIED` | Stage 2 | Cedar evaluation returned DENY |
| `BUDGET_EXCEEDED` | Stage 2 | Budget constraint violated |
| `SCOPE_VIOLATION` | Stage 2 | Action/resource outside capability scope |
| `RISK_THRESHOLD` | Stage 2 | Risk attribute exceeds configured threshold |
| `TOOL_NOT_IN_SCOPE` | Stage 2 | LLM-requested tool not in capability scope |
| `MALFORMED_REQUEST` | Interceptor | Cannot parse request into Execution Envelope |
| `AUTHORITY_UNAVAILABLE` | Pre-flight | Cannot reach Authority for capability issuance |
| `POLICY_BUNDLE_STALE` | Stage 2 | Policy bundle TTL expired, fail-closed |
| `CREDENTIAL_INJECTION_FAILED` | Cred Injector | Cannot fetch/inject credentials |
| `CONNECTOR_TIMEOUT` | Connector | Upstream target did not respond in time |

## Audit Event Format

Audit events are structured, signed records emitted for every enforcement decision:

```json
{
  "event_id": "uuid-v7",
  "session_id": "...",
  "token_id": "...",
  "agent_id": "...",
  "action": "http_get | http_post | execute_tool | llm_call",
  "resource": "target endpoint or tool name",
  "decision": "ALLOW | DENY | ABORT",
  "deny_reason": "REASON_CODE (if denied)",
  "enforcement_latency_us": 450,
  "context_hash": "sha256 of Cedar eval context",
  "bundle_version": "v1.2.3",
  "timestamp_ns": 1711360800000000000,
  "signature": "ECDSA signature over all preceding fields"
}
```

## Pagination Strategy

Not applicable for V1. gRPC streaming handles continuous data flow (policy bundles, revocations). No REST endpoints with paginated collections.

## Decision Relationships

- Protobuf definitions in `firma-proto` are the single source of truth for all inter-component contracts
- Same `.proto` files generate Rust server/client code (via Tonic) and can generate Go/Python/TypeScript client SDKs for the Capability Library
- HTTP proxy error responses use a Firma-specific JSON format (not gRPC) because agents interact via standard HTTP — they don't know they're talking to Firma
- Audit event format is designed for append-only sinks (stdout JSON lines or file in OSS V1) — no query API in V1
