# Domain Design Decisions

Reference material for Inception phase. These are design decisions and domain concepts extracted from early architectural thinking — use them as input when elaborating intents, units, and stories.

---

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
3. Apply budget/scope/threshold checks via pre-computed context attributes (risk is a static attribute in V1, not dynamic scoring)
4. Outcomes: ALLOW → Connector, DENY → structured response, ABORT → kill in-flight

**Response-path evaluation** (for LLM tool calls):

- Sidecar also evaluates LLM responses on the return path
- LLM Response Parser converts provider-specific format (OpenAI `function_call`, Anthropic `tool_use`) to canonical Execution Envelope
- Denied tool calls are stripped; a denial reason is injected so the LLM self-corrects
- This is defense-in-depth: response-path (is the tool allowed?) + request-path (is this specific API call allowed?)

---

## Execution Envelope

The core protocol unit. Immutable once created — enrichment produces derived structures.

| Field | Contents |
| ------- | ---------- |
| `intent` | Action type, target resource, action-specific parameters |
| `capability` | Signed capability token (PASETO v4 or JWT RS256) |
| `metadata` | Session ID, agent ID, timestamp, trace ID, budget consumed |
| `provenance` | Reserved/nullable in V1 — future hash chain for session provenance |

---

## Sidecar Internal Components

| Component | Responsibility | Performance Target |
| ----------- | --------------- | -------------------- |
| **Interceptor** | Capture outbound traffic, parse into Execution Envelope | — |
| **Stage 1** | Token parse, signature verify, expiry check, revocation bloom filter | < 1ms p95 |
| **Stage 2 (CEE)** | Cedar context build, policy eval, budget/scope/threshold checks | < 200µs p95 |
| **Credential Injector** | Inject secrets after ALLOW, before Connector dispatch | — |
| **Connector** | Translate Envelope → target protocol, apply technical constraints | — |
| **LLM Response Parser** | Parse provider-specific LLM responses (tool calls) into canonical Execution Envelopes for response-path evaluation | — |
| **Audit Emitter** | Emit signed enforcement events to stdout/file sinks | Async, non-blocking |
| **Policy Bundle Cache** | In-memory Cedar policy set, refreshed via WatchPolicyBundle stream | Hot-reload < 500ms |
| **Revocation Cache** | Bloom filter + LRU cache, updated via WatchRevocations stream | Propagation < 1s p99 |

## Mini Authority Internal Components

| Component | Responsibility |
| ----------- | --------------- |
| **Cedar Policy Loader** | Read `.cedar` files from disk at startup, watch for changes |
| **IssueCapability RPC** | Evaluate issuance request against policies, return signed PASETO v4/JWT token |
| **WatchPolicyBundle RPC** | Server-streaming: push current bundle on connect, then incremental updates |
| **WatchRevocations RPC** | Server-streaming: push revocation events (file-based in Mini Authority) |
| **Token Generator** | Sign capability tokens using Capability Library (PASETO v4 default, JWT RS256 fallback) |

All Authority RPCs require an authenticated caller identity. OSS V1 intentionally leaves the bootstrap authentication mechanism deployment-specific, but anonymous issuance is not allowed.

---

## Interception Modes

| Mode | Mechanism | Agent Config Required |
|------|-----------|----------------------|
| HTTP Proxy (default) | Agent sets `HTTP_PROXY=http://localhost:8080` | Env var only |
| gRPC Hook | Programmatic interceptor in agent process | Code integration |
| Unix Socket | Local socket, no port binding | Socket path config |
| eBPF (roadmap) | Kernel-level capture | None |

All modes produce the same output: a structured Execution Envelope passed to Stage 1.

---

## Failure Modes

| Scenario | Default Behavior |
| ---------- | ----------------- |
| Authority down at session start | Fail closed — DENY with AUTHORITY_UNAVAILABLE |
| Policy bundle stream disconnected, TTL valid | Continue degraded — serve from cache, log warnings |
| Policy bundle stream disconnected, TTL expired | Fail closed — deny all with POLICY_BUNDLE_STALE |
| Revocation stream delayed | Continue degraded — existing cache valid, log warnings |
| Audit file sink unavailable | Log error and fall back to stdout if configured; OSS V1 has no remote replay/WAL path |
| Connector timeout | Abort in-flight — CONNECTOR_TIMEOUT to agent |
| Credential injection failed | Fail closed — DENY, no call dispatched |
| Sidecar restart | In-process state lost — budget counters reset, sessions cleared. Agents must re-issue capabilities. Known V1 limitation (no persistent state). |
| Policy files malformed at startup | Fail fast — refuse to start with clear error. No partial policy loading. |
| Config invalid at startup | Fail fast — refuse to start. Validate all config before binding ports or accepting connections. |

**Fail-closed by default.** The Sidecar denies requests when uncertain rather than allowing potentially unauthorized actions.

---

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

---

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

---

## Performance Targets (V1)

| Metric | Target |
| -------- | -------- |
| Stage 1 latency | < 1ms p95 |
| Stage 2 latency (CEE) | < 200µs p95 |
| End-to-end Sidecar overhead | < 3ms p95 |
| Memory footprint | < 100 MB RSS |
| Throughput (single instance) | 5k–20k req/s |
| Policy hot-reload | < 500ms |
| Revocation propagation | < 1s p99 |

---

## Operational Concerns

### Health & Readiness

Both `opensidecar` and `openauthority-authority` (Mini Authority) expose health and readiness endpoints:

- **Liveness** (`/healthz`): Process is alive and responding
- **Readiness** (`/readyz`): Ready to serve traffic — policy bundle loaded, Authority connection established (Sidecar), policy files parsed (Mini Authority)

Required for Kubernetes liveness/readiness probes and useful for Docker health checks.

### Graceful Shutdown

On SIGTERM:

1. Stop accepting new connections
2. Drain in-flight requests (configurable timeout, default 30s)
3. Close gRPC streams (WatchPolicyBundle, WatchRevocations)
4. Flush pending audit events
5. Exit

### Metrics

Prometheus-compatible metrics endpoint (`/metrics`) exposing:

- Enforcement decision counters (ALLOW/DENY/ABORT by stage and reason)
- Enforcement latency histograms (Stage 1, Stage 2, end-to-end)
- Active sessions / connections
- Policy bundle version and age
- Revocation cache size

---

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

---

## HTTP Proxy Response Format

### Enforcement Denial Responses (Sidecar → Agent)

| Scenario | HTTP Status | Body Format |
|----------|-------------|-------------|
| ALLOW | Original upstream response | Passthrough (unchanged) |
| DENY (Stage 1) | 403 Forbidden | `{"openauthority_decision": "DENY", "reason": "TOKEN_EXPIRED", "detail": "..."}` |
| DENY (Stage 2) | 403 Forbidden | `{"openauthority_decision": "DENY", "reason": "POLICY_DENIED", "detail": "...", "action": "...", "resource": "..."}` |
| DENY (malformed) | 400 Bad Request | `{"openauthority_decision": "DENY", "reason": "MALFORMED_REQUEST", "detail": "..."}` |
| ABORT / Internal failure | 503 Service Unavailable | `{"openauthority_decision": "ABORT", "reason": "...", "detail": "..."}` |

### Error Response Structure

```json
{
  "openauthority_decision": "DENY | ABORT",
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
| `SCOPE_VIOLATION` | Stage 2 | Action, resource, or context attribute outside capability scope |
| `RISK_THRESHOLD` | Stage 2 | Static risk attribute exceeds configured threshold (V1: no dynamic scoring) |
| `TOOL_NOT_IN_SCOPE` | Stage 2 | LLM-requested tool not in capability scope |
| `MALFORMED_REQUEST` | Interceptor | Cannot parse request into Execution Envelope |
| `AUTHORITY_UNAVAILABLE` | Pre-flight | Cannot reach Authority for capability issuance |
| `POLICY_BUNDLE_STALE` | Stage 2 | Policy bundle TTL expired, fail-closed |
| `CREDENTIAL_INJECTION_FAILED` | Cred Injector | Cannot fetch/inject credentials |
| `CONNECTOR_TIMEOUT` | Connector | Upstream target did not respond in time |

---

## LLM Response-Path Rewriting

When the Sidecar denies a tool call detected in an LLM response:

- The denied tool call is stripped from the response
- A denial marker (`OPENAUTHORITY_DENY`) is injected in the provider-appropriate format
- Agent sees a normal-looking response (no OpenAuthority-specific handling needed)
- LLM self-corrects on the next turn

The rewriting logic is provider-agnostic: a pluggable LLM Response Parser normalizes provider-specific formats (e.g., OpenAI `function_call`, Anthropic `tool_use`) before enforcement, and re-serializes after.

---

## Audit Event Format

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

---

## V1 Scope Boundary

**Not in OSS V1**: Trust graph, dynamic risk engine, multi-tenant control plane, compliance-grade audit backend, enterprise memory governance, Cedar policy compiler/UI, escalation engine, provenance chain verification.

**Enterprise upgrade path**: Replace Mini Authority with OpenAuthority Authority (config-only swap: `openauthority.authority: FA_URL`). Sidecar binary is identical.

---

## Tech Stack Rationale

### Why Pingora

`ProxyHttp` trait hooks map directly to enforcement phases: `request_filter()` for identity/provider detection, `upstream_request_filter()` for credential injection, `upstream_response_body_filter()` for LLM response parsing and Cedar evaluation. Chunk-oriented body filters are ideal for SSE event-level filtering (tool call events get Cedar eval; text events pass through at zero added latency). Synchronous filters are sufficient — Cedar eval is in-process, sub-millisecond. Proven at 40M+ req/s at Cloudflare.

Why Pingora over Axum/Hyper: The sidecar's critical path is LLM response inspection and tool call extraction — a response-inspecting proxy workload. Pingora's `ProxyHttp` trait provides purpose-built lifecycle hooks for this, vs. Axum/Hyper which require more custom plumbing for proxy-style response body interception. Actix-web lacks Tower/Tonic interop. Rama is pre-1.0.

### Decision Relationships

- Pingora for sidecar HTTP + Tonic for Authority gRPC supports the compact two-binary architecture without separate gateway processes
- rustls + rcgen enables transparent HTTPS interception without OpenSSL dependency, simplifying static binary distribution
- Cedar policy engine is the same engine used by AWS Verified Permissions — strong formal verification properties for security-critical eval
- Tower middleware ecosystem is shared across all framework components, enabling consistent request/response interception patterns
- Protobuf definitions in `openauthority-proto` are the single source of truth for all inter-component contracts
- Same `.proto` files generate Rust server/client code (via Tonic) and can generate Go/Python/TypeScript client SDKs for the Capability Library
- HTTP proxy error responses use a OpenAuthority-specific JSON format (not gRPC) because agents interact via standard HTTP — they don't know they're talking to OpenAuthority
- Audit event format is designed for append-only sinks (stdout JSON lines or file in OSS V1) — no query API in V1
