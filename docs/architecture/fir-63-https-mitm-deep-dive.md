# FIR-63 Deep Dive: HTTPS TLS MITM Interception

## Purpose

This document defines the implementation baseline and phased execution plan for FIR-63: restoring L7 policy and audit on HTTPS traffic by adding explicit TLS MITM interception in `firma-sidecar`, with trust bootstrap in `firma-run`.

Primary objective:

- Keep FIR-61/FIR-63 routing guarantees and fail-closed posture.
- Move HTTPS from CONNECT host:port policy only to method/path-level policy enforcement and audit.

## Current Status (As Of 2026-04-27)

### What is already implemented

1. Structural routing and fail-closed runtime in `firma-run`:
- sandbox wrapper + proxy wiring in `crates/firma-run/src/runtime.rs` and `crates/firma-run/src/routing.rs`
- Linux `bwrap` confinement and resolver override in `crates/firma-run/src/backend/linux_bwrap.rs`

2. Sidecar HTTP interception + CONNECT support:
- `CONNECT` handling path in `crates/firma-sidecar/src/interceptor/http.rs`
- CONNECT authorization/audit surface in `crates/firma-sidecar/src/handler.rs` (`handle_connect`)
- CONNECT integration tests in `crates/firma-sidecar/src/interceptor/http.rs` (allow/deny + byte relay)
- HTTPS MITM runtime in `crates/firma-sidecar/src/interceptor/https_mitm.rs`
- MITM config + validation in `crates/firma-sidecar/src/config.rs` (`interceptor.https_mitm`)
- startup wiring in `crates/firma-sidecar/src/startup/interceptor.rs`
- HTTPS L7 integration test (`test_proxy_connect_mitm_intercepts_and_applies_l7_deny`)

3. E2E harness already validates HTTPS CONNECT path at destination level:
- `scripts/e2e-firma-run.sh --https-check`

### What is not implemented yet

1. `firma-run` trust bootstrap for managed sandbox clients:
- profile/env/mount system exists, but no profile-level CA propagation contract has been finalized for Python/Node/curl/Java/Go runtimes.

2. Expanded HTTPS parity coverage in E2E harness:
- sidecar has MITM unit/integration coverage, but `scripts/e2e-firma-run.sh` still needs explicit HTTPS L7 assertions across representative agent profiles.

3. Performance and observability hardening:
- MITM hot path is functional, but dedicated perf benchmarks and handshake/cert-cache metrics are a follow-up.

## Gap Summary Against FIR-63 Goals

- Destination-level HTTPS control: available now.
- Request-level HTTPS control: available for intercepted hosts.
- HTTPS L7 audit events: available for intercepted hosts.
- Credential injection on HTTPS decrypted path: available for intercepted hosts (via existing handler pipeline).
- Operator-controlled interception scope: available via `intercept_hosts` / `bypass_hosts` / `strict_hosts`.
- Trust bootstrap failure fail-closed guarantees: still partially open until firma-run profile bootstrap is completed.

## Architecture Target

### High-level data path (MITM enabled)

1. Agent sends `CONNECT host:port` to sidecar.
2. Sidecar applies pre-handshake policy gate (host:port, profile scope, readiness).
3. Sidecar returns `200 Connection Established`.
4. Sidecar performs downstream TLS server handshake with dynamically issued cert (signed by sidecar CA).
5. Sidecar parses decrypted inner HTTP request.
6. Request goes through existing normalizer/pipeline/credential-injection path (same as HTTP semantics).
7. Sidecar establishes upstream TLS client connection to target with normal CA validation.
8. Sidecar forwards request/response while preserving audit/event semantics.

### Mandatory invariants

- No silent fallback from MITM failure to blind tunnel for intercepted hosts.
- Fail-closed remains default for startup/runtime readiness failures.
- MITM must be explicitly scoped by configuration.
- Audit records must indicate HTTPS-intercepted vs CONNECT-only flows.

## Configuration Model (Implemented)

Add explicit MITM section under `[interceptor.https_mitm]`:

- `enabled` (bool, default `true`)
- `ca_cert_path` (optional; default under `ca.dir`)
- `ca_key_path` (optional; default under `ca.dir`)
- `intercept_hosts` (list, explicit allowlist)
- `bypass_hosts` (list)
- `cert_ttl_secs` (default 86400)
- `cert_cache_capacity` (bounded cache)
- `strict_hosts` (optional list; deny if MITM cannot be applied)

Behavioral rule:

- Host in `intercept_hosts` and not in `bypass_hosts` => MITM path required.
- Host in `strict_hosts` => any MITM failure is deterministic deny (no tunnel fallback).

## Phased Implementation Plan

### Phase 0: Contracts, Threat Model, and Baseline Instrumentation

Scope:
- Lock exact MITM behavior contracts, error reasons, and fallback policy.
- Add structured metrics/log fields to differentiate CONNECT-only vs HTTPS-intercepted flows.

Deliverables:
- FIR-63 implementation checklist (this document + issue checklist).
- Finalized deny reason matrix for MITM failure classes.

Gate:
- Team sign-off on fallback rules and strict-host semantics.

### Phase 1: Sidecar CA and Certificate Authority Runtime

Scope:
- Implement CA load-or-generate path under `ca.dir`.
- Harden file permissions for private key material.
- Separate audit signing key and MITM CA key responsibilities.

Code touchpoints:
- `crates/firma-sidecar/src/config.rs`
- new startup/helper module for CA state (e.g., `startup/https_mitm.rs`)

Gate:
- Unit tests: generate/load/reload; invalid/missing key paths; permission checks.

### Phase 2: Dynamic Per-Host Cert Issuance + Cache

Scope:
- Implement cert issuance signed by sidecar CA for DNS/IP SAN targets.
- Add bounded + TTL cache and concurrency-safe single-generation per host.

Code touchpoints:
- new MITM cert module (e.g., `interceptor/http/mitm_cert.rs`)
- interceptor runtime state initialization

Gate:
- Unit/concurrency tests: no duplicate generation under parallel requests; cache TTL/eviction behavior.

### Phase 3: HTTPS MITM Transport Path in HTTP Interceptor

Scope:
- Replace tunnel-only flow for intercepted hosts with downstream TLS termination + upstream TLS re-encryption.
- Reuse existing `RequestHandler` pipeline after decrypt.
- Keep CONNECT-only path for bypass hosts or MITM disabled mode.

Code touchpoints:
- `crates/firma-sidecar/src/interceptor/http.rs`
- `crates/firma-sidecar/src/handler.rs` (audit/decode metadata extensions as needed)

Gate:
- Integration tests:
  - allowed host/path succeeds through decrypted path
  - denied path returns deterministic deny JSON
  - CONNECT-only bypass host keeps current behavior

### Phase 4: `firma-run` Trust Bootstrap for Managed Profiles

Scope:
- Export/mount sidecar CA material into sandbox and configure trust env for managed runtimes.
- Define explicit profile behavior for `generic` and `codex` with deterministic failure semantics.

Code touchpoints:
- `crates/firma-run/src/config.rs`
- `crates/firma-run/src/profile.rs`
- `crates/firma-run/src/runtime.rs`
- `crates/firma-run/src/backend/linux_bwrap.rs`

Gate:
- Integration tests per profile with HTTPS client matrix (curl + Python/Node baseline).
- Bootstrap failures fail closed for strict-intercept hosts.

### Phase 5: Full E2E and Regression Matrix

Scope:
- Extend `scripts/e2e-firma-run.sh` with HTTPS L7 assertions (not only CONNECT success).
- Preserve existing FIR-61 HTTP and CONNECT-only regression behavior.

Required scenarios:
- HTTPS allow by method/path for intercepted host.
- HTTPS deny by method/path for intercepted host.
- sidecar unavailable => zero egress.
- trust bootstrap broken => deterministic failure (no bypass).

Gate:
- `make check` clean.
- E2E matrix green in local reproducible run.

### Phase 6: Rollout, Performance, and Operator Guidance

Scope:
- Feature-flag off by default initially.
- Add staging guidance for host-by-host opt-in.
- Document pinning behavior and runtime compatibility caveats.

Deliverables:
- docs update (`docs/configuration.md`, `docs/firma-run-local-testing.md`, architecture/security docs)
- performance snapshot under concurrent TLS handshakes

Gate:
- explicit rollout checklist and rollback path documented.

## Testing Strategy Breakdown

### Unit tests

- CA load/generate/persist and invalid-key failure paths.
- Cert issuance for DNS and IP SAN.
- Host matching precedence: intercept vs bypass vs strict.
- Cache TTL/capacity eviction.

### Integration tests (sidecar crate)

- MITM enabled, host intercepted: decrypted request reaches normalizer/handler.
- Path-level policy deny on HTTPS produces canonical deny JSON.
- Credential injection still applied for HTTPS via decrypted path.

### E2E tests (`firma-run`)

- Sandbox HTTPS request produces method/path-level audit.
- Sidecar outage remains fail-closed.
- Broken trust bootstrap causes deterministic failure.

## Risk Register

1. Runtime trust-store variance across clients:
- Mitigation: start with explicit supported matrix (curl, Python requests/httpx, Node) and document gaps.

2. Certificate pinning incompatibility:
- Mitigation: document expected failure mode; support bypass hosts for pinned endpoints.

3. Performance overhead on TLS-heavy traffic:
- Mitigation: cert cache, connection reuse where safe, perf benchmark gate before default-on changes.

4. Operational CA lifecycle complexity:
- Mitigation: clear operator docs for CA persistence, rotation, and incident rollback.

## Future-Proofing Seams

- Keep MITM implementation behind explicit config gate and host scoping.
- Separate CA manager and cert issuer modules from interceptor request logic.
- Keep CONNECT-only mode as intentional, test-covered fallback mode.
- Preserve connector/pipeline API compatibility so future transports (gRPC/eBPF) can reuse policy path.
- Keep profile-level trust bootstrap declarative so additional runtimes can be added without redesign.

## Completion Criteria for FIR-63

FIR-63 is considered complete only when all are true:

1. HTTPS via `firma run` emits L7-normalized audit (method/path) for intercepted hosts.
2. Cedar decisions apply at HTTPS route/action level, not just CONNECT destination level.
3. Trust/bootstrap failures are deterministic and fail-closed where configured.
4. Existing HTTP and CONNECT-only regression suites remain green.
5. Operator documentation covers trust model, interception scope, and known limitations.
