---
intent: 006-sidecar-proxy-enforcement
phase: inception
status: units-decomposed
updated: 2026-04-05T12:00:00Z
---

# Sidecar Proxy & Enforcement - Unit Decomposition

## Units Overview

This intent decomposes into 6 units of work, following domain-driven decomposition for a backend-api project:

### Unit 1: 001-proxy-core

**Description**: Pingora-based HTTP/HTTPS proxy interceptor with TLS MITM, configuration, startup lifecycle, health/readiness endpoints, graceful shutdown, and proxy-path denial response formatting.

**Assigned Requirements**: FR-1, FR-11, FR-12

**Stories**:
- 001-http-proxy-listener
- 002-https-mitm-interception
- 003-ca-keypair-management
- 004-proxy-denial-response-format
- 005-config-and-startup
- 006-health-readiness-shutdown

**Deliverables**:
- Pingora `ProxyHttp` implementation with request/response lifecycle hooks
- Dynamic TLS cert generation with domain caching
- CA keypair management (generate, persist, reuse)
- TOML config parsing with CLI overrides
- `/healthz`, `/readyz` endpoints
- Graceful SIGTERM shutdown with drain

**Dependencies**:
- Depends on: None (foundational transport layer)
- Depended by: All other units integrate through proxy-core lifecycle hooks

**Estimated Complexity**: XL

---

### Unit 2: 002-enforcement-pipeline

**Description**: The core two-phase enforcement engine: intent normalization with the v0.1 Canonical Action Class Registry, Stage 1 capability token validation, and Stage 2 Cedar policy evaluation via the Constraint Enforcement Engine (CEE).

**Assigned Requirements**: FR-2, FR-3, FR-4

**Stories**:
- 001-intent-normalizer
- 002-unclassified-intent-denial
- 003-stage1-token-validation
- 004-stage2-cedar-evaluation
- 005-two-phase-pipeline-integration

**Deliverables**:
- Intent normalizer with configurable mapping table
- ExecutionEnvelope builder with all five intent sub-fields
- Stage 1: PASETO v4 parse + verify + expiry + revocation check
- Stage 2: Cedar context builder + policy evaluation + scope check
- Integrated pipeline returning Decision (ALLOW/DENY)

**Dependencies**:
- Depends on: firma-core (traits: `TokenVerifier`, `PolicyEvaluator`), firma-proto
- Depended by: 004-llm-response-parser (reuses enforcement pipeline for tool call evaluation)

**Estimated Complexity**: XL

---

### Unit 3: 003-policy-revocation

**Description**: Dual-mode data sources for Cedar policy bundles and token revocation lists. File-based mode for standalone operation, gRPC streaming mode for Authority integration. Includes the two-layer revocation cache (bloom filter + LRU).

**Assigned Requirements**: FR-5, FR-6

**Stories**:
- 001-file-policy-source
- 002-grpc-policy-source
- 003-file-revocation-source
- 004-grpc-revocation-source
- 005-revocation-cache

**Deliverables**:
- `PolicySource` trait + file implementation (load, watch, hot-reload)
- `PolicySource` gRPC implementation (WatchPolicyBundle stream)
- `RevocationSource` trait + file implementation
- `RevocationSource` gRPC implementation (WatchRevocations stream)
- Two-layer cache: bloom filter (O(1) negative) + LRU (confirmed positives)
- TTL enforcement with fail-closed on expiry

**Dependencies**:
- Depends on: firma-proto (gRPC service definitions), firma-core (trait definitions)
- Depended by: 002-enforcement-pipeline (Stage 1 reads revocation cache, Stage 2 reads policy bundle)

**Estimated Complexity**: L

---

### Unit 4: 004-llm-response-parser

**Description**: Response-path evaluation for LLM tool call instructions. Pluggable provider parsers (OpenAI, Anthropic, Gemini) that detect tool calls in both streaming (SSE) and non-streaming responses, evaluate each through the enforcement pipeline, and rewrite denied calls to provider-native structured denial results.

**Assigned Requirements**: FR-7

**Stories**:
- 001-openai-parser
- 002-anthropic-parser
- 003-gemini-parser
- 004-sse-stream-reassembly
- 005-denial-rewrite-synthesis

**Deliverables**:
- `LlmResponseParser` trait with provider detection
- OpenAI parser (function_call + tool_calls, streaming + non-streaming)
- Anthropic parser (tool_use blocks, streaming + non-streaming)
- Gemini parser (functionCall, streaming + non-streaming)
- SSE chunk reassembly for cross-chunk tool calls
- Provider-native denial result rewriting and synthesis

**Dependencies**:
- Depends on: 002-enforcement-pipeline (evaluates extracted tool calls through Stage 1 + Stage 2)
- Depended by: 001-proxy-core (integrated as Pingora response filter)

**Estimated Complexity**: XL

---

### Unit 5: 005-connector-credentials

**Description**: Outbound HTTP request dispatch and credential injection. Translates authorized ExecutionEnvelopes into HTTP requests, manages connection pooling and timeouts, and injects target-system credentials from configuration without exposing them to the agent.

**Assigned Requirements**: FR-8, FR-9

**Stories**:
- 001-http-connector
- 002-credential-provider-trait
- 003-credential-injection

**Deliverables**:
- Generic HTTP connector with connection pooling and timeout enforcement
- `CredentialProvider` trait + config-based implementation
- Transport-ready execution view derivation with credential injection
- Fail-closed on injection failure (`CREDENTIAL_INJECTION_FAILED`)

**Dependencies**:
- Depends on: None (independent outbound dispatch)
- Depended by: 001-proxy-core (called after Stage 2 ALLOW to dispatch authorized requests)

**Estimated Complexity**: M

---

### Unit 6: 006-audit-observability

**Description**: Audit event emission with ECDSA signing and Prometheus metrics. Serializes ExecutionEvents with all FEP §15 fields, signs them, and emits to configurable sinks (stdout, file). Exposes Prometheus-compatible `/metrics` endpoint.

**Assigned Requirements**: FR-10, FR-13

**Stories**:
- 001-execution-event-schema
- 002-ecdsa-audit-signing
- 003-audit-sinks
- 004-prometheus-metrics

**Deliverables**:
- `ExecutionEvent` struct with all FEP §15 minimum fields
- ECDSA signature computation over event fields
- `AuditSink` trait + stdout/file implementations
- Async non-blocking emission (best-effort, event loss on crash acceptable in V1)
- Prometheus `/metrics` endpoint with decision counters, latency histograms, gauges

**Dependencies**:
- Depends on: None (receives events from enforcement pipeline)
- Depended by: 001-proxy-core (audit emitter called after every enforcement decision)

**Estimated Complexity**: M

---

## Requirement-to-Unit Mapping

- **FR-1**: HTTP/HTTPS Proxy Interceptor → `001-proxy-core`
- **FR-2**: Intent Normalizer / Envelope Builder → `002-enforcement-pipeline`
- **FR-3**: Stage 1 — Capability Validation → `002-enforcement-pipeline`
- **FR-4**: Stage 2 — CEE → `002-enforcement-pipeline`
- **FR-5**: Policy Source (Dual-Mode) → `003-policy-revocation`
- **FR-6**: Revocation Source (Dual-Mode) → `003-policy-revocation`
- **FR-7**: LLM Response Parser → `004-llm-response-parser`
- **FR-8**: Generic HTTP Connector → `005-connector-credentials`
- **FR-9**: Credential Injector → `005-connector-credentials`
- **FR-10**: Audit Emitter → `006-audit-observability`
- **FR-11**: HTTP Proxy Response Format → `001-proxy-core`
- **FR-12**: Configuration & Startup → `001-proxy-core`
- **FR-13**: Prometheus Metrics → `006-audit-observability`

## Unit Dependency Graph

```text
003-policy-revocation ──────┐
                            ▼
                    002-enforcement-pipeline ──► 004-llm-response-parser
                            │                           │
005-connector-credentials ──┤                           │
                            ▼                           ▼
006-audit-observability ──► 001-proxy-core ◄────────────┘
                            (integrates all units)
```

## Execution Order

Based on dependencies and parallelization opportunities:

1. **Phase 1** (parallel): 002-enforcement-pipeline, 003-policy-revocation, 005-connector-credentials, 006-audit-observability — all independent
2. **Phase 2**: 004-llm-response-parser — depends on enforcement-pipeline
3. **Phase 3**: 001-proxy-core integration bolts — wires all units into Pingora lifecycle
