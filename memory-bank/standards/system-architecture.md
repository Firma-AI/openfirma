# System Architecture

## Overview

Firma OSS follows a sidecar proxy architecture with a two-phase enforcement pipeline. The system is split into two binaries (`firma-sidecar` + `firma-authority`) communicating via gRPC, with all enforcement happening locally in the Sidecar — no hot-path network calls.

OSS V1 deploys these as separate local processes or services. Docker and Kubernetes package the same split architecture rather than embedding the Authority into the Sidecar.

## Architecture Style

**Sidecar proxy pattern** with local enforcement

The Sidecar runs as a co-located process alongside each AI agent. All agent outbound traffic routes through the Sidecar (via HTTP_PROXY, gRPC hook, or Unix socket). The Sidecar evaluates every request locally through a two-stage enforcement pipeline before forwarding to the target.

```text
┌─────────────────────────────────────────────────────────┐
│  Agent Host / Container                                 │
│                                                         │
│  ┌──────────┐    HTTP_PROXY     ┌────────────────────┐  │
│  │ AI Agent │ ───────────────── │   Firma Sidecar    │  │
│  └──────────┘                   │                    │  │
│                                 │  ┌──────────────┐  │  │
│                                 │  │ Interceptor  │  │  │
│                                 │  └──────┬───────┘  │  │
│                                 │         │          │  │
│                                 │  ┌──────▼───────┐  │  │
│                                 │  │   Stage 1    │  │  │
│                                 │  │  (Cap Valid)  │  │  │
│                                 │  └──────┬───────┘  │  │
│                                 │         │          │  │
│                                 │  ┌──────▼───────┐  │  │
│                                 │  │   Stage 2    │  │  │
│                                 │  │  (CEE/Cedar) │  │  │
│                                 │  └──────┬───────┘  │  │
│                                 │         │          │  │
│                                 │  ┌──────▼───────┐  │  │
│                                 │  │  Cred Inject │  │  │
│                                 │  └──────┬───────┘  │  │
│                                 │         │          │  │
│                                 │  ┌──────▼───────┐  │  │
│                                 │  │  Connector   │──┼──┼──► External System
│                                 │  └──────────────┘  │  │
│                                 │                    │  │
│                                 │  ┌──────────────┐  │  │
│                                 │  │ Audit Emitter│──┼──┼──► Audit Sink
│                                 │  └──────────────┘  │  │
│                                 └────────────────────┘  │
│                                         │ gRPC          │
│                                         ▼               │
│                                 ┌────────────────────┐  │
│                                 │  Mini Authority    │  │
│                                 │  (file-based)      │  │
│                                 └────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

**Key invariant**: The Authority is contacted only during pre-flight (capability issuance). Stage 1 and Stage 2 are fully local — no network calls on the hot path.

## Component Architecture

### Workspace Crates

| Crate | Type | Responsibility |
|-------|------|----------------|
| `firma-sidecar` | Binary | HTTP proxy, enforcement pipeline, audit, credential injection |
| `firma-authority` | Binary | Mini Authority — policy loading, capability issuance, gRPC streams |
| `firma-core` | Library | Shared types, Execution Envelope, capability tokens, Cedar wrapper, error types |
| `firma-proto` | Library | Protobuf/gRPC service definitions, generated code |

### Sidecar Internal Components

| Component | Responsibility | Performance Target |
|-----------|---------------|--------------------|
| **Interceptor** | Capture outbound traffic, parse into Execution Envelope | — |
| **Stage 1** | Token parse, signature verify, expiry check, revocation bloom filter | < 1ms p95 |
| **Stage 2 (CEE)** | Cedar context build, policy eval, budget/scope/threshold checks | < 200µs p95 |
| **Credential Injector** | Inject secrets after ALLOW, before Connector dispatch | — |
| **Connector** | Translate Envelope → target protocol, apply technical constraints | — |
| **Audit Emitter** | Emit signed enforcement events to stdout/file sinks | Async, non-blocking |
| **Policy Bundle Cache** | In-memory Cedar policy set, refreshed via WatchPolicyBundle stream | Hot-reload < 500ms |
| **Revocation Cache** | Bloom filter + LRU cache, updated via WatchRevocations stream | Propagation < 1s p99 |

### Mini Authority Internal Components

| Component | Responsibility |
|-----------|---------------|
| **Cedar Policy Loader** | Read `.cedar` files from disk at startup, watch for changes |
| **IssueCapability RPC** | Evaluate issuance request against policies, return signed PASETO v4/JWT token |
| **WatchPolicyBundle RPC** | Server-streaming: push current bundle on connect, then incremental updates |
| **WatchRevocations RPC** | Server-streaming: push revocation events (file-based in Mini Authority) |
| **Token Generator** | Sign capability tokens using Capability Library (PASETO v4 default, JWT RS256 fallback) |

All Authority RPCs require an authenticated caller identity. OSS V1 intentionally leaves the bootstrap authentication mechanism deployment-specific, but anonymous issuance is not allowed.

## Interception Modes

| Mode | Mechanism | Agent Config Required |
|------|-----------|----------------------|
| HTTP Proxy (default) | Agent sets `HTTP_PROXY=http://localhost:8080` | Env var only |
| gRPC Hook | Programmatic interceptor in agent process | Code integration |
| Unix Socket | Local socket, no port binding | Socket path config |
| eBPF (roadmap) | Kernel-level capture | None |

All modes produce the same output: a structured Execution Envelope passed to Stage 1.

## Two-Phase Enforcement Pipeline

Every outbound call passes through both phases sequentially in the same process:

**Stage 1 — Capability Validation** (token layer):

1. Deserialize capability token from Execution Envelope
2. Verify cryptographic signature (Ed25519 for PASETO v4, RS256 for JWT)
3. Check expiry
4. Check revocation via bloom filter (O(1)) + LRU cache
5. On pass → Stage 2. On fail → DENY with structured reason.

**Stage 2 — Constraint Enforcement Engine (CEE)** (policy layer):

1. Build Cedar request context from envelope fields + local state + runtime signals
2. Evaluate Cedar policies (deterministic: same context + same bundle = same result)
3. Apply budget/scope/threshold checks via pre-computed context attributes
4. Outcomes: ALLOW → Connector, DENY → structured response, ABORT → kill in-flight

**Response-path evaluation** (for LLM tool calls):

- Sidecar also evaluates LLM responses on the return path
- LLM Response Parser converts provider-specific format (OpenAI `function_call`, Anthropic `tool_use`) to canonical Execution Envelope
- Denied tool calls are stripped; a denial reason is injected so the LLM self-corrects
- This is defense-in-depth: response-path (is the tool allowed?) + request-path (is this specific API call allowed?)

## Execution Envelope

The core protocol unit. Immutable once created — enrichment produces derived structures.

| Field | Contents |
|-------|----------|
| `intent` | Action type, target resource, action-specific parameters |
| `capability` | Signed capability token (PASETO v4 or JWT RS256) |
| `metadata` | Session ID, agent ID, timestamp, trace ID, budget consumed |
| `provenance` | Reserved/nullable in V1 — future hash chain for session provenance |

## Failure Modes

| Scenario | Default Behavior |
|----------|-----------------|
| Authority down at session start | Fail closed — DENY with AUTHORITY_UNAVAILABLE |
| Policy bundle stream disconnected, TTL valid | Continue degraded — serve from cache, log warnings |
| Policy bundle stream disconnected, TTL expired | Fail closed — deny all with POLICY_BUNDLE_STALE |
| Revocation stream delayed | Continue degraded — existing cache valid, log warnings |
| Audit file sink unavailable | Log error and fall back to stdout if configured; OSS V1 has no remote replay/WAL path |
| Connector timeout | Abort in-flight — CONNECTOR_TIMEOUT to agent |
| Credential injection failed | Fail closed — DENY, no call dispatched |

**Fail-closed by default.** The Sidecar denies requests when uncertain rather than allowing potentially unauthorized actions.

## Security Patterns

### Defense in Depth

- **Stage 1**: Cryptographic token validation (forgery, tampering, expiry, revocation)
- **Stage 2**: Semantic policy enforcement (scope, budget, context, namespace isolation)
- **Connector**: Protocol-level constraints (rate limits, schema validation)
- **Response-path**: LLM tool call evaluation (tool allow/deny independent of API call allow/deny)

### Separation of Concerns

- **Cedar policies** own all business/authorization logic — never in connectors
- **Connectors** own technical constraints (rate limits, schema validation) — never business policy
- **Credential Injector** owns secret handling — agents never see credentials

### Trust Boundaries

- Agent-supplied fields in Execution Envelope are **untrusted** unless verified or recomputed by Sidecar
- All enforcement is local — no external system can influence an enforcement decision
- Cedar evaluation is deterministic — same context + same bundle = same decision, always

## Capability Lifecycle

```text
ISSUED → ACTIVE → IN USE → ACTIVE (reuse) → EXPIRED
                                            → REVOKED
                                            → ABORTED
```

- Tokens are multi-use within their TTL
- Sidecar does NOT auto-renew tokens in V1
- On TOKEN_EXPIRED, agent must call IssueCapability again
- Token lifecycle ≠ session lifecycle (a session may span multiple tokens)

## Performance Targets (V1)

| Metric | Target |
|--------|--------|
| Stage 1 latency | < 1ms p95 |
| Stage 2 latency (CEE) | < 200µs p95 |
| End-to-end Sidecar overhead | < 3ms p95 |
| Memory footprint | < 100 MB RSS |
| Throughput (single instance) | 5k–20k req/s |
| Policy hot-reload | < 500ms |
| Revocation propagation | < 1s p99 |

## V1 Scope Boundary

**Not in OSS V1**: Trust graph, dynamic risk engine, multi-tenant control plane, compliance-grade audit backend, enterprise memory governance, Cedar policy compiler/UI, escalation engine, provenance chain verification.

**Enterprise upgrade path**: Replace Mini Authority with Firma Authority (config-only swap: `firma.authority: FA_URL`). Sidecar binary is identical.
