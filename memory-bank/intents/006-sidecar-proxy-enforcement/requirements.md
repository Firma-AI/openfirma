---
intent: 006-sidecar-proxy-enforcement
phase: inception
status: inception-complete
created: 2026-04-04T12:00:00Z
updated: 2026-04-05T12:00:00Z
---

# Requirements: Sidecar Proxy & Enforcement

## Intent Overview

Build the real `firma-sidecar` — the primary enforcement component that sits between every AI agent and the external world. Implements a Pingora-based HTTP/HTTPS proxy with the full two-phase enforcement pipeline (Stage 1 capability validation + Stage 2 Cedar policy evaluation), intent normalization with the v0.1 Canonical Action Class Registry, response-path LLM tool call evaluation with pluggable provider parsers, generic HTTP connector, config-based credential injection, ECDSA-signed audit emission, and dual-mode policy/revocation sourcing (file-based default, gRPC Authority client optional).

## Business Goals

| Goal | Success Metric | Priority |
|------|----------------|----------|
| Enforce every outbound agent call | No call reaches a target system without passing Stage 1 + Stage 2 | Must |
| Meet enforcement latency targets | < 3ms p95 end-to-end Sidecar-added overhead | Must |
| Transparent proxy integration | Agent requires only `HTTP_PROXY` env var + CA cert trust — zero code changes | Must |
| Deterministic policy enforcement | Same context + same bundle = same decision, every time | Must |
| Transparent LLM tool call enforcement | Denied tool calls converted to provider-native structured denial results; agent runtime receives a consumable tool output expressing the denial | Must |
| Pluggable extensibility | Community can add LLM providers, credential backends, audit sinks, policy sources | Should |

---

## Functional Requirements

### FR-1: HTTP/HTTPS Proxy Interceptor (Pingora)
- **Description**: Pingora-based proxy listening on a configurable port (default `:8080`). Handles both plain HTTP requests and HTTPS `CONNECT` tunnels. For HTTPS, performs MITM TLS interception using dynamically generated certificates (rcgen) signed by a Sidecar-managed CA, with rustls for TLS termination. The agent trusts the Sidecar CA via standard env vars (`REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`). On first run, generates a CA keypair if none exists, persisted to a configurable path. **Note**: This FR describes one OSS interception mode for FEP (HTTP/HTTPS proxy). FEP itself is transport-agnostic; this intent does not redefine FEP as an HTTP/TLS transport protocol. Future interception modes (e.g. eBPF, gRPC) use the same enforcement pipeline with a different interception layer.
- **Acceptance Criteria**:
  - Plain HTTP requests are intercepted and the full request (method, headers, body, URL) is available for enforcement
  - HTTPS CONNECT requests trigger dynamic cert generation for the target domain
  - Dynamic certs are cached per-domain (no duplicate generation for concurrent requests to the same host)
  - Agent with CA cert trusted receives valid TLS connection to proxy-impersonated target
  - CA keypair is generated on first run and reused across restarts
  - Configurable listen address and port
- **Priority**: Must

### FR-2: Intent Normalizer / Envelope Builder
- **Description**: Deterministic, rule-based component that maps each intercepted request into a canonical `ExecutionEnvelope` with a normalized `intent.action_class` from the v0.1 Canonical Action Class Registry. Uses a configurable mapping table that matches on, e.g. for HTTP interception surfaces, `(method, host, path_pattern, body_fields)` to produce the canonical action class and normalized resource. The key invariant is deterministic canonicalization of a bounded raw runtime surface; the matching mechanism may vary by interception mode. Populates all five intent sub-fields: `action_class`, `resource`, `parameters` (or parameter hash), `raw_transport`, `raw_action_ref`. Falls back to `system.execute` for ambiguous raw execution surfaces. Returns `DENY: UNCLASSIFIED_INTENT` for protected actions that cannot be deterministically mapped.
- **Acceptance Criteria**:
  - All 15 v0.1 registry action classes are supported in the mapping configuration
  - Cross-transport normalization works: same semantic action from different transports produces the same `action_class`
  - `DENY: UNCLASSIFIED_INTENT` returned for unmappable protected actions (fail-closed)
  - `system.execute` used only as bounded high-risk fallback, not as convenience class
  - Mapping rules are loaded from configuration (not hardcoded)
  - Normalized Execution Envelope is immutable after creation
- **Priority**: Must

### FR-3: Stage 1 — Capability Validation
- **Description**: First enforcement phase. Validates the capability token carried in the Execution Envelope: parse (PASETO v4 via `firma-core`), cryptographic signature verification against the Authority public key, expiry check, and revocation check via bloom filter + LRU cache. No Cedar evaluation. Failure produces immediate DENY with structured reason code (`TOKEN_INVALID`, `TOKEN_EXPIRED`, `TOKEN_REVOKED`). Authority is never contacted.
- **Acceptance Criteria**:
  - PASETO v4 tokens parsed and signature verified using `firma-core` `TokenVerifier` trait
  - Expired tokens rejected with `TOKEN_EXPIRED`
  - Revoked tokens rejected via bloom filter (O(1) negative check) + LRU cache for confirmed positives
  - Forged/tampered tokens rejected with `TOKEN_INVALID`
  - Stage 1 latency < 1ms p95
  - On pass, envelope proceeds to Stage 2; on fail, structured DENY returned immediately
- **Priority**: Must

### FR-4: Stage 2 — Constraint Enforcement Engine (CEE)
- **Description**: Second enforcement phase. Builds the Cedar request context from envelope fields, Sidecar local state, and runtime signals. Evaluates Cedar policies from the current policy bundle. Result is binary ALLOW or DENY. Fully local — no external calls. The context schema is **generic and configurable** — the set of context attributes available to Cedar policies is defined by the Cedar entity schema and populated by pluggable context providers, not hardcoded to any specific domain (e.g., payments). Context Builder operates on a previously normalized Execution Envelope and does not infer action class from raw transport input. The Context Builder must not read LLM scratchpads, reasoning traces, prompt windows, or orchestration memory directly. Agent-originated metadata is admitted only as explicit untrusted attributes (see Cedar context: operator-defined custom attributes below).
- **Acceptance Criteria**:
  - Cedar context includes a **base set** of attributes derived from the Execution Envelope: `action_class`, `resource`, `agent_id`, `session_id`, `timestamp`
  - Cedar context includes **Sidecar-managed attributes** computed locally: `budget_remaining` (generic budget tracking), `request_count` (session-scoped counter), `action_count_window` (configurable sliding window counter per action class)
  - Cedar context supports **operator-defined custom attributes**: additional key-value pairs injected from agent-supplied metadata (treated as untrusted) or from Sidecar configuration (treated as trusted)
  - Context attribute schema is defined by the Cedar entity schema (`.cedarschema`), not hardcoded in the Sidecar binary
  - Cedar evaluation is deterministic: same context + same bundle = same result
  - Scope check: action must be within capability token's allowed action set
  - Stage 2 latency < 200µs p95
  - ALLOW forwards to Credential Injector → Connector; DENY returns structured response
- **Priority**: Must

### FR-5: Policy Source (Dual-Mode)
- **Description**: Abstracted behind a `PolicySource` trait with two implementations. **File mode**: loads all `.cedar` files from a configurable directory at startup, watches for filesystem changes, and hot-reloads (atomic swap of in-memory policy set). File mode exists as a temporary testing mechanism to allow intent 006 development and testing in isolation while intent 005 (Mini Authority) is not yet complete. It is not intended as a long-term operational mode. **gRPC mode (primary)**: connects to `AuthorityService.WatchPolicyBundle` server-streaming RPC, receives initial bundle on connect and incremental updates. Activated when `--authority-url` is configured. Both modes maintain bundle version tracking and a configurable TTL (default 30s). If TTL expires without a successful refresh, Sidecar enters fail-closed mode (DENY all with `POLICY_BUNDLE_STALE`). If a new bundle fails to parse, the Sidecar retains the last valid set.
- **Acceptance Criteria**:
  - File mode: all `.cedar` files in configured directory are loaded and compiled at startup
  - File mode: filesystem changes detected and new bundle hot-reloaded within 500ms
  - File mode: malformed `.cedar` files at startup cause fail-fast (refuse to start)
  - File mode: malformed `.cedar` files during hot-reload are rejected; last valid bundle retained
  - gRPC mode: connects to Authority, receives initial bundle, applies incremental updates
  - gRPC mode: stream disconnect triggers TTL countdown; on expiry, fail-closed
  - gRPC mode: reconnect resumes with full bundle push
  - Bundle version tracked and included in audit events
  - `PolicySource` trait allows community implementations
- **Priority**: Must

### FR-6: Revocation Source (Dual-Mode)
- **Description**: Abstracted behind a `RevocationSource` trait with two implementations. **File mode (default)**: loads revocation entries from a configurable JSON file, watches for changes. **gRPC mode (optional)**: connects to `AuthorityService.WatchRevocations` server-streaming RPC. Both modes populate a two-layer cache: bloom filter for O(1) negative checks, LRU cache for confirmed revocations. No network I/O at check time (Stage 1).
- **Acceptance Criteria**:
  - Bloom filter provides sub-microsecond negative revocation check
  - LRU cache stores confirmed revocations for positive matches
  - File mode: revocation file changes trigger cache update
  - gRPC mode: revocation events received on stream update bloom filter + LRU
  - Revocation propagation < 1s p99 from source update to Stage 1 rejection
  - `RevocationSource` trait allows community implementations
- **Priority**: Must

### FR-7: LLM Response Parser (Response-Path Evaluation)
- **Description**: Pluggable component behind an `LlmResponseParser` trait that intercepts LLM API responses on the return path, detects tool call instructions in provider-specific formats, converts each to a canonical Execution Envelope, and evaluates it through Stage 1 + Stage 2. On DENY: rewrites the provider-specific payload only to the extent necessary to surface a structured denial result to the agent runtime — semantically equivalent to a tool output expressing the denial, in the provider-native format, so the agent loop can read and reason about it. The goal is a *simulated structured tool output* consumable by the agent, not suppression of the tool call. On ALLOW: forwards the response unchanged. V1 ships with parsers for OpenAI (Responses API `function_call` output items + Chat Completions API `function_call` / `tool_calls`), Anthropic (`tool_use`), and Google Gemini (`functionCall`). Handles both non-streaming (full JSON response) and streaming (SSE `data:` events) responses. Provider detection is automatic based on the target host.
- **Acceptance Criteria**:
  - OpenAI parser: detects Responses API `function_call` output items and Chat Completions API `function_call`/`tool_calls` in both streaming and non-streaming responses; API path-based format selection
  - Anthropic parser: detects `tool_use` content blocks in both streaming and non-streaming responses
  - Gemini parser: detects `functionCall` in both streaming and non-streaming responses
  - SSE streaming: tool calls split across multiple chunks are correctly reassembled before evaluation
  - On DENY (rewrite path): provider payload rewritten in-flight to a provider-native structured denial result (e.g. a tool result block with `firma_decision: DENY` and `reason` fields) — agent runtime receives a consumable tool output, not a stripped response
  - On DENY (synthesis path): parser synthesizes an equivalent provider-native tool-result message and injects it into the return stream — agent runtime observes a structured denial result semantically equivalent to a denied tool output. Both paths are valid implementations; both must be tested independently.
  - On ALLOW: response forwarded to agent byte-identical (no modification)
  - Unknown/unsupported providers: response forwarded without response-path evaluation (request-path enforcement still applies)
  - `LlmResponseParser` trait documented for community provider contributions
  - Each parser has comprehensive test coverage against recorded real LLM responses
- **Priority**: Must

### FR-8: Generic HTTP Connector
- **Description**: Translates the authorized Execution Envelope + transport-ready derived execution view (produced by FR-9) into the outbound HTTP request to the target system. Manages connection pooling, timeout enforcement, and retry policy. Returns a `ConnectorResponse` to the Sidecar. Does not make authorization decisions, modify intent/capability/metadata fields of the ExecutionEnvelope, implement business logic, or source credentials independently. Conforms to FEP §9 Connector Boundary Rules.
- **Acceptance Criteria**:
  - Authorized envelope + derived execution view translated to correct HTTP request (method, URL, headers, body)
  - Connection pooling with configurable pool size per target host
  - Configurable per-target timeout (default 30s)
  - Connector does not inspect or modify intent, capability, or metadata fields
  - ConnectorResponse includes status code, headers, body, and latency for audit
  - Connector timeout returns `CONNECTOR_TIMEOUT` to agent
- **Priority**: Must

### FR-9: Credential Injector
- **Description**: Runs after Stage 2 ALLOW, before the Connector is invoked. Derives a transport-ready execution view from the immutable ExecutionEnvelope by resolving and attaching target-system credentials — the ExecutionEnvelope itself is never mutated. The agent never handles credentials. V1 implements basic config-based injection: a mapping table in configuration that specifies per-target credentials (from env vars or config values). Abstracted behind a `CredentialProvider` trait for future extensibility (Vault, AWS Secrets Manager, etc.). If credential derivation fails, returns `DENY: CREDENTIAL_INJECTION_FAILED` — no call dispatched.
- **Acceptance Criteria**:
  - Per-target credential mapping in configuration (target host → header name + value source)
  - Credentials sourced from environment variables or config file values
  - Supports `Authorization: Bearer {token}`, custom header injection, and query parameter injection
  - Agent never sees injected credentials in the request or response
  - Failed injection produces `DENY: CREDENTIAL_INJECTION_FAILED` (fail-closed)
  - `CredentialProvider` trait allows community implementations
- **Priority**: Must

### FR-10: Audit Emitter
- **Description**: Fires after every enforcement decision (ALLOW, DENY, ABORT). Serializes an `ExecutionEvent` containing all FEP §15 minimum audit fields: event_id (UUID v7), session_id, agent_id, token_id, action_class, resource, decision, deny_reason, enforcement_latency_us, context_hash, bundle_version, registry_version, trace_id, timestamp_ns, and an ECDSA signature over all preceding fields. V1 implements two sinks: stdout (structured JSON lines, default) and file (append-only). Abstracted behind an `AuditSink` trait for future extensibility (gRPC streaming, WAL, etc.). Emission is asynchronous and non-blocking — enforcement decisions are not delayed by audit writes. **V1 delivery guarantee**: best-effort async only. Events buffered in-process are lost on crash — there is no WAL or durable queue in V1. Durable audit delivery (WAL-backed sinks, at-least-once guarantees) is a post-V1 enhancement.
- **Acceptance Criteria**:
  - Every ALLOW, DENY, and ABORT decision emits an audit event (no silent decision paths)
  - All FEP §15 minimum fields present in every event
  - ECDSA signature computed over all event fields; verifiable with the Sidecar's audit signing key
  - stdout sink: one JSON line per event, compatible with `jq` and log aggregators
  - file sink: append-only writes to configurable path
  - Multiple sinks can be active simultaneously
  - Audit emission does not block the enforcement hot path
  - `AuditSink` trait allows community implementations
- **Priority**: Must

### FR-11: HTTP Proxy Response Format
- **Description**: This format applies to **API/proxy-path denials** — cases where the agent made a direct HTTP call that was denied at Stage 1 or Stage 2. Denial responses follow a Firma-specific JSON format (not gRPC, since agents interact via standard HTTP). Includes `firma_decision`, `reason` (reason code), `detail` (human-readable), `request_id` (UUID v7), and `timestamp`. HTTP status codes: 403 for Stage 1/Stage 2 denials, 400 for malformed requests, 503 for internal failures. **Tool-path denials** (LLM tool calls denied on the response path) follow provider-native structured tool-result semantics as defined in FR-7 — they are not expressed as HTTP 4xx responses.
- **Acceptance Criteria**:
  - All reason codes from the domain design decisions doc are supported: `TOKEN_INVALID`, `TOKEN_EXPIRED`, `TOKEN_REVOKED`, `POLICY_DENIED`, `BUDGET_EXCEEDED`, `SCOPE_VIOLATION`, `RISK_THRESHOLD`, `TOOL_NOT_IN_SCOPE`, `UNCLASSIFIED_INTENT`, `MALFORMED_REQUEST`, `AUTHORITY_UNAVAILABLE`, `POLICY_BUNDLE_STALE`, `CREDENTIAL_INJECTION_FAILED`, `CONNECTOR_TIMEOUT`
  - 403 for enforcement denials, 400 for malformed input, 503 for internal/infrastructure failures
  - Response body is valid JSON matching the documented schema
  - ALLOW responses pass through the upstream response unchanged
  - Tool-path denials (FR-7) are not expressed as HTTP 4xx — they follow provider-native structured tool-result format
- **Priority**: Must

### FR-12: Configuration & Startup
- **Description**: Sidecar configured via a TOML config file with CLI argument overrides. Exposes health (`/healthz`) and readiness (`/readyz`) endpoints. Readiness requires: policy bundle loaded, CA keypair available, all configured credential providers initialized. Graceful shutdown on SIGTERM: stop accepting new connections, drain in-flight requests (configurable timeout, default 30s), flush pending audit events, exit. Fail-fast on invalid config or malformed policy files at startup.
- **Acceptance Criteria**:
  - TOML config file with CLI overrides for common options (listen addr, policy dir, authority URL, log level)
  - `/healthz` returns 200 when process is alive
  - `/readyz` returns 200 only when policy bundle loaded and sidecar is ready to serve
  - SIGTERM triggers graceful shutdown with configurable drain timeout
  - In-flight requests complete during drain; new connections rejected
  - Pending audit events flushed before exit
  - Invalid config at startup: fail-fast with clear error message
  - Malformed policy at startup: fail-fast (do not start with partial policies)
- **Priority**: Must

### FR-13: Prometheus Metrics
- **Description**: Exposes a `/metrics` endpoint with Prometheus-compatible metrics for observability. Enforcement decision counters (ALLOW/DENY/ABORT by stage and reason), latency histograms (Stage 1, Stage 2, end-to-end), active sessions/connections, policy bundle version and age, revocation cache size.
- **Acceptance Criteria**:
  - `/metrics` returns Prometheus exposition format
  - Counter: `firma_decisions_total{stage, decision, reason}`
  - Histogram: `firma_stage1_latency_seconds`, `firma_stage2_latency_seconds`, `firma_enforcement_latency_seconds`
  - Gauge: `firma_active_connections`, `firma_policy_bundle_age_seconds`, `firma_revocation_cache_size`
  - Info: `firma_policy_bundle_version`
- **Priority**: Should

---

## Non-Functional Requirements

### Performance
| Requirement | Metric | Target |
|-------------|--------|--------|
| Stage 1 latency | p95 | < 1ms |
| Stage 2 latency (CEE) | p95 | < 200µs |
| End-to-end enforcement overhead | p95 | < 3ms |
| Throughput (single instance) | req/s | 5k–20k |
| Policy hot-reload | time to new bundle active | < 500ms |
| Revocation propagation | p99 | < 1s |

### Memory
| Requirement | Metric | Target |
|-------------|--------|--------|
| RSS steady-state | Memory | < 100 MB |
| Includes | — | Policy bundle cache, revocation LRU, in-flight state, audit buffer, cert cache |

### Security
| Requirement | Standard | Notes |
|-------------|----------|-------|
| Fail-closed default | — | Deny on uncertainty: expired TTL, parse failure, missing config, unknown action |
| No bypass path | FEP §3 [I-F1] | Every Connector-dispatched request has passed Stage 1 + Stage 2 |
| ECDSA-signed audit | — | Every audit event is signed; verifiable without Sidecar access |
| Credential isolation | — | Agent never sees target-system credentials |
| Immutable envelope | FEP §3 [I-E3] | No component modifies intent/capability/metadata after Interceptor creation |

### Reliability
| Requirement | Metric | Target |
|-------------|--------|--------|
| Policy stream disconnect (TTL valid) | Behavior | Continue degraded, serve from cache |
| Policy stream disconnect (TTL expired) | Behavior | Fail-closed, deny all with POLICY_BUNDLE_STALE |
| Revocation stream delayed | Behavior | Continue degraded, existing cache valid |
| Audit sink unavailable | Behavior | Log error; events still written to remaining sinks |
| Connector timeout | Behavior | CONNECTOR_TIMEOUT to agent; token state unchanged |
| Sidecar crash | Audit delivery | Best-effort loss — in-process buffered events not yet flushed are lost; no WAL in V1 |

### Testability (HIGH ATTENTION — ALL RISK AREAS)
| Risk Area | Required Coverage | Rationale |
|-----------|-------------------|-----------|
| SSE streaming body filter | Recorded real LLM responses for all 3 providers; chunked at arbitrary byte boundaries; partial tool calls spanning chunks; multi-tool responses; streaming + non-streaming | Most technically treacherous — tool calls split across SSE chunks, in-flight rewriting |
| Pingora lifecycle integration | Integration tests exercising full request/response cycle through proxy hooks; error paths in each lifecycle phase; connection reuse and keepalive | Sparse documentation; lifecycle hook ordering is critical |
| Dynamic TLS cert generation | Concurrent requests to same domain; cert cache correctness; CA key persistence; invalid/expired CA; untrusted agent scenarios | Concurrency in cert generation; cache invalidation |
| Cedar context schema | Schema-contract tests ensuring context fields match policy expectations; every context attribute tested in isolation; policies that should match do match, policies that shouldn't don't | Silent policy non-match is invisible — the most dangerous failure mode |
| Fail-closed discipline | Every error path tested to confirm it ends in DENY (not panic, not pass-through); malformed input, missing config, expired state, injection failures | Requires consistent discipline across every error handler in the codebase |

---

## Constraints

### Technical Constraints

**Intent-specific constraints**:
- Depends on `firma-core` (intent 002) for `CapabilityClaims`, `ExecutionEnvelope`, `Decision`, `TokenVerifier`, `PolicyEvaluator` traits
- Depends on `firma-proto` (intent 003) for `AuthorityService` gRPC definitions, `PolicyBundleUpdate`, `RevocationEvent` messages
- Must use Pingora as HTTP proxy engine (tech stack decision)
- Must use Cedar (`cedar-policy` crate) for Stage 2 policy evaluation
- Must use Tonic for gRPC Authority communication (tech stack decision)
- Must use rustls + rcgen for TLS interception (no OpenSSL dependency)
- LLM Response Parser must be provider-agnostic behind a trait; V1 ships OpenAI, Anthropic, Gemini
- Credential Injector must be backend-agnostic behind a trait; V1 ships config-based only
- Audit Emitter must be sink-agnostic behind a trait; V1 ships stdout + file only
- Policy/Revocation sources must be backend-agnostic behind traits; V1 ships file + gRPC

### Business Constraints
- V1 scope only — no dynamic risk engine, no trust graph, no escalation engine, no provenance chain verification
- Provenance field present in Execution Envelope schema but not populated by runtime
- Static risk_score attribute only (no dynamic scoring)
- Single-tenant (no per-org policy namespacing)

### Out of Scope
- **Native database wire protocol interception**: The V1 sidecar is an HTTP proxy. It does not intercept native database connections (PostgreSQL, MySQL, etc.) that use binary wire protocols on dedicated ports. Database enforcement in V1 is limited to: (1) HTTP-based database APIs (Supabase, Hasura, PostgREST) intercepted as normal HTTP traffic, and (2) LLM tool calls that wrap database access intercepted on the response path. Direct SQL connections from agent tool code bypass the proxy entirely. Future interception modes (eBPF, database wire protocol proxy) would use the existing `DbQueryParams` action type in the Execution Envelope — the enforcement pipeline does not change, only the interception layer.
- **eBPF interception mode**: Kernel-level traffic capture is a roadmap item, not V1.
- **gRPC interception**: V1 intercepts HTTP/HTTPS only. gRPC-based agent-to-service communication is not intercepted by the HTTP proxy.
- **Vault / dynamic secret providers**: V1 ships config-based credential injection only. The `CredentialProvider` trait enables future Vault integration.
- **gRPC / WAL audit sinks**: V1 ships stdout + file sinks only with best-effort async delivery (buffered events are lost on crash). The `AuditSink` trait enables future gRPC streaming and WAL-backed at-least-once implementations.
- **Escalation / HITL enforcement**: No `ESCALATE` outcome in V1. Binary ALLOW/DENY only.

---

## Assumptions

| Assumption | Risk if Invalid | Mitigation |
|------------|-----------------|------------|
| Pingora's `ProxyHttp` trait hooks map cleanly to enforcement phases | Major rearchitecture of proxy layer | Spike/prototype the Pingora integration early; validate lifecycle hook ordering |
| SSE streaming from LLM providers follows standard `text/event-stream` format | Response parser fails to detect tool calls | Test against recorded real responses from all 3 providers |
| Cedar policy evaluation stays < 200µs for realistic policy bundles | Stage 2 becomes a latency bottleneck | Benchmark with reference policy set of increasing complexity; set CI regression gate |
| rcgen can generate certs fast enough for high-concurrency HTTPS interception | TLS interception becomes a bottleneck | Cache generated certs per domain; benchmark concurrent cert generation |
| firma-core types and traits (intent 002) are stable | Interface changes cascade into sidecar | Intent 002 is complete; traits are the stable contract |
| firma-proto gRPC definitions (intent 003) are stable | gRPC client breaks on proto changes | Intent 003 is complete; proto is the stable contract |

---

## Open Questions

| Question | Owner | Due Date | Resolution |
|----------|-------|----------|------------|
| How does the sidecar discover which capability token to use for a given request? Token-per-session vs token-in-header vs sidecar-managed session? | — | Before construction | Needs design decision during domain model stage |
| Should the sidecar support multiple concurrent sessions (multiple agents)? | — | Before construction | Architecture decision — one sidecar per agent vs shared sidecar |
| What is the exact Cedar entity schema for V1? (entity types, action types, context attributes) | — | During construction | Defined during Cedar context schema design |
