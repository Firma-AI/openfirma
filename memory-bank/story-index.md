# Global Story Index

## Overview

- **Total stories**: 67
- **Complete**: 17
- **Generated**: 28
- **Planned**: 22
- **Last updated**: 2026-04-26

---

## Stories by Intent

### 001-project-scaffolding

#### Unit: 001-workspace-setup

- [x] **001-workspace-and-crates** (001-workspace-setup): Cargo workspace, 4 crates, dependency graph, stub entrypoints - Must - GENERATED
- [x] **002-clippy-and-fmt** (001-workspace-setup): Workspace-level Clippy lints and formatting config - Must - GENERATED
- [x] **003-ci-pipeline** (001-workspace-setup): GitHub Actions CI workflow - Must - GENERATED
- [x] **004-makefile** (001-workspace-setup): Makefile mirroring CI - Must - GENERATED

### 002-core-types-shared-library

#### Unit: 001-types-and-traits

- [x] **001-capability-token-types** (002-types-and-traits): CapabilityClaims struct, TokenState enum - Must - GENERATED
- [x] **002-execution-types** (002-types-and-traits): ExecutionEnvelope, ExecutionContext, sub-structs - Must - GENERATED
- [x] **003-decision-and-errors** (002-types-and-traits): Decision enum, DenyReason, TokenError, EvaluationError - Must - GENERATED
- [x] **004-trait-interfaces** (002-types-and-traits): PolicyEvaluator, TokenSigner, TokenVerifier, PolicyBundleStore, RevocationStore - Must - GENERATED

#### Unit: 002-paseto-v4

- [x] **001-paseto-signer** (003-paseto-v4): PasetoV4Signer implementing TokenSigner - Must - GENERATED
- [x] **002-paseto-verifier** (003-paseto-v4): PasetoV4Verifier implementing TokenVerifier - Must - GENERATED
- [x] **003-token-round-trip-tests** (003-paseto-v4): Comprehensive sign/verify/reject test suite - Must - GENERATED

### 003-grpc-protocol-wire-contract

*(No stories tracked — construction was completed directly)*

### 004-example-agents

#### Unit: 001-python-openai-agent

- [x] **001-agent-scaffold** (004-python-openai-agent): Agent definition, REPL, Makefile, .env.sample - Must - COMPLETE
- [x] **002-tool-definitions** (004-python-openai-agent): 9 tools across 5 categories (network, DB, file, email, shell) - Must - COMPLETE
- [x] **003-database-seed** (004-python-openai-agent): SQLite seed data and database service - Must - COMPLETE

#### Unit: 002-typescript-adk-agent

- [x] **001-agent-scaffold** (005-typescript-adk-agent): Agent definition, session loop, Makefile, .env.sample - Must - COMPLETE
- [x] **002-tool-definitions** (005-typescript-adk-agent): 9 tools with Zod schemas across 5 categories - Must - COMPLETE
- [x] **003-database-seed** (005-typescript-adk-agent): SQLite seed data and database service - Must - COMPLETE

### 006-sidecar-proxy-enforcement

#### Unit: 001-proxy-core

- [ ] **001-http-proxy-listener** (001-proxy-core): Plain HTTP proxy interception via Pingora - Must - ✅ GENERATED
- [ ] **002-https-mitm-interception** (001-proxy-core): HTTPS CONNECT + TLS MITM with dynamic cert gen - Must - ✅ GENERATED
- [ ] **003-ca-keypair-management** (001-proxy-core): CA keypair generation, persistence, reuse - Must - ✅ GENERATED
- [ ] **004-proxy-denial-response-format** (001-proxy-core): Firma JSON denial responses (403/400/503) - Must - ✅ GENERATED
- [ ] **005-config-and-startup** (001-proxy-core): TOML config + CLI overrides + fail-fast - Must - ✅ GENERATED
- [ ] **006-health-readiness-shutdown** (001-proxy-core): Health, readiness, graceful SIGTERM shutdown - Must - ✅ GENERATED

#### Unit: 002-enforcement-pipeline

- [ ] **001-intent-normalizer** (002-enforcement-pipeline): Mapping table + action class registry → ExecutionEnvelope - Must - ✅ GENERATED
- [ ] **002-unclassified-intent-denial** (002-enforcement-pipeline): DENY: UNCLASSIFIED_INTENT for unmappable actions - Must - ✅ GENERATED
- [ ] **003-stage1-token-validation** (002-enforcement-pipeline): PASETO v4 parse, verify, expiry, revocation - Must - ✅ GENERATED
- [ ] **004-stage2-cedar-evaluation** (002-enforcement-pipeline): Cedar context build + policy eval + scope check - Must - ✅ GENERATED
- [ ] **005-two-phase-pipeline-integration** (002-enforcement-pipeline): Wire Stage 1 → Stage 2, unified Decision - Must - ✅ GENERATED

#### Unit: 003-policy-revocation

- [ ] **001-file-policy-source** (003-policy-revocation): Load .cedar files, watch, hot-reload - Must - ✅ GENERATED
- [ ] **002-grpc-policy-source** (003-policy-revocation): WatchPolicyBundle stream, TTL/fail-closed - Must - ✅ GENERATED
- [ ] **003-file-revocation-source** (003-policy-revocation): JSON file-based revocation with watch - Must - ✅ GENERATED
- [ ] **004-grpc-revocation-source** (003-policy-revocation): WatchRevocations stream, cache updates - Must - ✅ GENERATED
- [ ] **005-revocation-cache** (003-policy-revocation): Bloom filter + LRU two-layer cache - Must - ✅ GENERATED

#### Unit: 004-llm-response-parser

- [ ] **001-openai-parser** (004-llm-response-parser): OpenAI function_call/tool_calls, streaming + non-streaming - Must - ✅ GENERATED
- [ ] **002-anthropic-parser** (004-llm-response-parser): Anthropic tool_use blocks, streaming + non-streaming - Must - ✅ GENERATED
- [ ] **003-gemini-parser** (004-llm-response-parser): Gemini functionCall, streaming + non-streaming - Must - ✅ GENERATED
- [ ] **004-sse-stream-reassembly** (004-llm-response-parser): Chunked SSE reassembly for cross-chunk tool calls - Must - ✅ GENERATED
- [ ] **005-denial-rewrite-synthesis** (004-llm-response-parser): Provider-native denial result rewriting/synthesis - Must - ✅ GENERATED

#### Unit: 005-connector-credentials

- [ ] **001-http-connector** (005-connector-credentials): Outbound dispatch, connection pooling, timeouts - Must - ✅ GENERATED
- [ ] **002-credential-provider-trait** (005-connector-credentials): CredentialProvider trait + config-based impl - Must - ✅ GENERATED
- [ ] **003-credential-injection** (005-connector-credentials): Derive transport view, inject creds, fail-closed - Must - ✅ GENERATED

#### Unit: 006-audit-observability

- [ ] **001-execution-event-schema** (006-audit-observability): ExecutionEvent with all FEP §15 fields - Must - ✅ GENERATED
- [ ] **002-ecdsa-audit-signing** (006-audit-observability): ECDSA signature over event fields - Must - ✅ GENERATED
- [ ] **003-audit-sinks** (006-audit-observability): stdout + file sinks, multi-sink, async non-blocking - Must - ✅ GENERATED
- [ ] **004-prometheus-metrics** (006-audit-observability): /metrics endpoint, counters, histograms, gauges - Should - ✅ GENERATED

### 007-firma-run-sandbox-launcher

#### Unit: 001-cli-runtime-orchestrator

- [ ] **001-cli-surface-and-arg-parsing** (001-cli-runtime-orchestrator): `firma run` command surface, parser, passthrough args - Must - PLANNED
- [ ] **002-process-supervision-and-signal-forwarding** (001-cli-runtime-orchestrator): Child lifecycle supervision and signal propagation - Must - PLANNED
- [ ] **003-tui-safe-stdio-passthrough** (001-cli-runtime-orchestrator): Interactive-safe TTY/stdin/stdout handling - Must - PLANNED
- [ ] **004-fail-closed-startup-order** (001-cli-runtime-orchestrator): Startup gates enforcing fail-closed launch order - Must - PLANNED

#### Unit: 002-bwrap-backend-contract

- [ ] **001-backend-trait-and-proof-objects** (002-bwrap-backend-contract): Pluggable backend trait and invariant proof objects - Must - PLANNED
- [ ] **002-bwrap-sandbox-launcher** (002-bwrap-backend-contract): Linux bubblewrap backend lifecycle implementation - Must - PLANNED
- [ ] **003-enterprise-backend-extension-seam** (002-bwrap-backend-contract): Additive enterprise backend extension seam - Must - PLANNED

#### Unit: 003-egress-routing-and-dns-confinement

- [ ] **001-sidecar-uds-bridge** (003-egress-routing-and-dns-confinement): Sandbox-local sidecar bridge over UDS path - Must - PLANNED
- [ ] **002-network-egress-lockdown** (003-egress-routing-and-dns-confinement): Structural no-bypass egress confinement - Must - PLANNED
- [ ] **003-dns-stub-and-resolver-wiring** (003-egress-routing-and-dns-confinement): Explicit DNS stub + resolver confinement path - Must - PLANNED
- [ ] **004-sidecar-unreachable-zero-egress** (003-egress-routing-and-dns-confinement): Sidecar outage fail-closed zero-egress invariants - Must - PLANNED

#### Unit: 004-identity-and-capability-lifecycle

- [ ] **001-deterministic-sandbox-id** (004-identity-and-capability-lifecycle): Deterministic per-run identity model - Must - PLANNED
- [ ] **002-attribution-header-injection** (004-identity-and-capability-lifecycle): Sidecar attribution identity propagation - Must - PLANNED
- [ ] **003-capability-rotation-contract** (004-identity-and-capability-lifecycle): Long-running capability renewal contract - Must - PLANNED

#### Unit: 005-profiles-and-config

- [ ] **001-config-schema-and-validation** (005-profiles-and-config): Config schema parsing and fail-fast validation - Must - PLANNED
- [ ] **002-generic-profile-default** (005-profiles-and-config): Built-in default generic profile behavior - Must - PLANNED
- [ ] **003-codex-profile-default** (005-profiles-and-config): Built-in codex profile behavior - Must - PLANNED
- [ ] **004-mount-env-passthrough-rules** (005-profiles-and-config): Explicit env/path passthrough rules - Must - PLANNED

#### Unit: 006-e2e-bench-and-docs

- [ ] **001-generic-profile-e2e** (006-e2e-bench-and-docs): Generic profile end-to-end mediation and fail-closed tests - Must - PLANNED
- [ ] **002-codex-profile-e2e** (006-e2e-bench-and-docs): Codex profile end-to-end mediation and UX tests - Must - PLANNED
- [ ] **003-benchmark-harness-and-json-artifacts** (006-e2e-bench-and-docs): Startup/overhead benchmark harness and JSON output - Must - PLANNED
- [ ] **004-readme-and-ops-guide** (006-e2e-bench-and-docs): FIR-61 docs and operator guidance - Must - PLANNED

---

## Stories by Status

- **Planned**: 22
- **Generated**: 39
- **In Progress**: 0
- **Completed**: 6
