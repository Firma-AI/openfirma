# Intent Plan — Firma OSS

## Approach Decisions

### Test-First with Early Example Agent

Instead of building all components in isolation and testing at the end, we introduce an example agent early (intent 004) that acts as a **living integration test**. It starts with mocks and swaps in real implementations as they're built. This validates proxy behavior with real HTTP traffic from day one.

### Project Scaffolding First

A dedicated scaffolding intent sets up the Cargo workspace with all four crates (`firma-core`, `firma-proto`, `firma-sidecar`, `firma-authority`) before any real implementation. This establishes crate boundaries, dependency graph, and CI from the start — avoiding painful restructuring later.

### Mock Strategy

Keep mocks thin — just enough to prove wiring works. The value is in the feedback loop, not elaborate fakes. Mocks are replaced incrementally as real components are built in later intents.

## Intent Ordering

| # | Intent | Purpose | Depends On |
|---|--------|---------|------------|
| 001 | Project scaffolding | Cargo workspace with `firma-core`, `firma-proto`, `firma-sidecar`, `firma-authority` stubs, CI pipeline, key traits with mock impls | — |
| 002 | Core types & shared library | Real `firma-core` — capability tokens (PASETO v4 / JWT RS256), Cedar wrapper, error types, storage traits, capability library | 001 |
| 003 | gRPC protocol & wire contract | `firma-proto` — Protobuf service definitions (AuthorityService RPCs: IssueCapability, WatchPolicyBundle, WatchRevocations), messages (ExecutionEnvelope, CapabilityToken), generated code | 001 |
| 004 | Example agents & test harness | Python + TypeScript agents exercising ALLOW/DENY/ABORT scenarios, example Cedar policies & base schema (entity types, action types, context attributes), mock authority, validates proxy flow end-to-end | 002, 003 |
| 005 | Mini Authority service | Real `firma-authority` — Cedar policy loader from `.cedar` files, IssueCapability RPC, WatchPolicyBundle streaming, WatchRevocations streaming, capability token generation | 002, 003 |
| 006 | Sidecar proxy & enforcement | Real `firma-sidecar` — Pingora HTTP proxy, Stage 1 (token parse, sig verify, revocation bloom filter), Stage 2 / CEE (context build, Cedar eval, budget/scope/threshold), generic HTTP connector, credential injector, audit emitter | 002, 003 |
| 007 | Firma Run sandbox launcher | `firma run` generic wrapper — sandboxed agent launch, mandatory sidecar routing, DNS confinement, built-in `generic` + `codex` profiles | 006 |
| 008 | Local dev mode | `firma dev up` orchestration — wires Mini Authority (:50051) + Sidecar (:8080) + Example Agent, Cedar hot-reload, audit to stdout, end-to-end demo in under 2 minutes | 004, 005, 006, 007 |

## V1 Scope Exclusions

Decisions made during inception that are explicitly out of scope for V1:

- **Capability Library in Go/Python/TypeScript**: V1 is Rust-only (`firma-core`). Agents interact via HTTP_PROXY — no agent-side SDK needed. Agent-side token inspection is a post-V1 nice-to-have.
- **budget_consumed / risk_score fields**: Removed from ExecutionMetadata/Context. Add back when computation/tracking mechanisms are designed.
- **provenance field**: Removed from ExecutionEnvelope. V1 placeholder with no implementation — add back when hash chain is designed.
- **BudgetExceeded / RiskThreshold deny reasons**: Deferred — corresponding data fields not yet present.

## Design Notes

### Operator File Count for Policy Setup

Current design requires operators to touch 4 files minimum (sidecar config, mapping rules, Cedar schema, Cedar policies). For the "try it in 5 minutes" tier this is too many. Ship sensible defaults: default mapping rules for OpenAI/Anthropic/Gemini, default `.cedarschema` matching the v0.1 action class registry, and a starter policy. Target: 2 files minimum (config + one policy). Address during intent 006 config story (bolt 007-proxy-core) or intent 007 local dev mode.

## Key Principles

- **Single enforcement plane remains Sidecar**: Policy decisions still happen in the Sidecar; runtime wrappers do not introduce a second policy engine.
- **Sandbox boundary is now required for complete coverage**: FIR-60 updated architecture direction on 2026-04-23. `firma-run` (FIR-61) moves the hard boundary to sandboxed execution plus mandatory sidecar routing so shell/subprocess/browser-originated traffic is structurally governed.
- **Natural build order**: Each intent builds on previous foundations.
- **Example agent as validator**: Intent 004 becomes the living integration test that proves the system works end-to-end as components are swapped from mock to real.
- **Defense-in-depth via deployment**: Container/sandbox isolation and sidecar policy enforcement are complementary, not interchangeable.
- **Cedar policies are content, not code**: The base schema and example policies ship with intent 004 to make the system usable from the first integration test. They evolve alongside the components they validate.

## Component Reference Mapping

How intents map to components from `firma_oss_component_reference.md`:

| Component Reference Section | Covered By Intent |
|----------------------------|-------------------|
| Section 3 — Mini Authority (policy loader, IssueCapability, WatchPolicyBundle, WatchRevocations, token gen) | 005 |
| Section 4 — Firma Sidecar (interceptor, execution envelope, Stage 1, Stage 2/CEE, local state, audit emitter, credential injector) | 006 |
| Section 5 — Capability Library (token validation, parse/verify/sign, PASETO/JWT, expiry/scope checks) | 002 (Rust core only — Go/Python/TS SDKs out of V1 scope) |
| Section 6 — Example Agents (Python, TypeScript) | 004 |
| Section 7 — Connector/Adapter Layer (generic HTTP connector) | 006 |
| Section 9 — Cedar Policies/Schema/Examples | 004 (base schema + examples), 005 (runtime loading) |
| Section 10 — Local Dev Mode (`firma dev up`) | 008 |
