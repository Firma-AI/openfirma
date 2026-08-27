# Firma Run + Sidecar Technical Relation

Status: active reference
Last updated: 2026-04-27
Owners: Runtime + Sidecar teams

## 1. Purpose

This document explains, in implementation-level detail, how `firma-run` and `firma-sidecar` work together to enforce outbound traffic policy for agent runtimes.

It is intended to be the common reference for:

- engineering implementation decisions,
- security/design reviews,
- onboarding and incident response,
- future extension work (new runtimes, stronger hardening, performance tuning).

The cross-component identity contract is documented separately in
[Sandbox Identity Boundary Contract](sandbox-identity.md).

## 2. Scope

In scope:

- `firma-run` runtime wrapper and sandbox launch behavior.
- Sidecar HTTP proxy interception path.
- HTTPS handling through `CONNECT` and TLS MITM.
- Current hardening baseline (fail-closed, CA handling, wildcard controls, tunnel lifetime bounds).
- Known limits and explicit next steps.

Out of scope:

- Authority internals (covered by authority docs).
- eBPF/kernel-level interception (future work).
- Full enterprise deployment controls (separate operational docs).

## 3. System Components

### 3.1 Runtime wrapper (`firma-run`)

Primary responsibilities:

- resolve runtime profile (`generic`, `codex`, config/CLI overrides),
- create deterministic run identity (`sandbox_id`, `session_id`, profile attribution),
- prepare selected backend (Linux `bwrap`, macOS `vz`, Windows `wsl2`),
- enforce fail-closed startup checks,
- launch wrapped command with routing/identity env.

Key files:

- `crates/firma-run/src/runtime.rs`
- `crates/firma-run/src/routing.rs`
- `crates/firma-run/src/profile.rs`
- `crates/firma-run/src/config.rs`
- `crates/firma-run/src/backend/linux_bwrap.rs`
- `crates/firma-run/src/dns_stub.rs`

### 3.2 Enforcement sidecar (`firma-sidecar`)

Primary responsibilities:

- intercept outgoing requests,
- normalize intent + evaluate policy,
- dispatch allowed requests through connector,
- emit audit events,
- fail closed on malformed/unsafe/unready conditions.

Key files:

- `crates/firma-sidecar/src/interceptor/http.rs`
- `crates/firma-sidecar/src/interceptor/https_mitm.rs`
- `crates/firma-sidecar/src/handler.rs`
- `crates/firma-sidecar/src/startup/interceptor.rs`
- `crates/firma-sidecar/src/config.rs`

## 4. End-to-End Data Flow

### 4.1 Launch path

1. `firma run -- <cmd>` resolves effective profile.
2. Backend prepares runtime artifacts.
3. Fail-closed check validates sidecar endpoint reachability.
4. Proxy env values are set for wrapped command (`HTTP_PROXY`, `HTTPS_PROXY`, etc.).
5. Wrapped process starts.

Linux structural mode:

- sandbox-local bridge path is used to route proxy traffic through controlled endpoint.
- sandbox `/etc/resolv.conf` is generated and mounted by `firma-run`.
- the resolver points at the sandbox-local DNS stub (`127.0.0.1:53`), not the
  host resolver.
- the DNS stub refuses lookups deterministically when the sandbox can bind
  port 53; in unprivileged bwrap mode where low-port bind is unavailable, the
  localhost resolver path still fails closed.
- HTTP proxy traffic continues to carry hostnames to the sidecar, and direct
  resolver use fails closed instead of using ambient host DNS.

### 4.2 HTTP request path

1. Sidecar receives HTTP request.
2. Request is parsed into `RawRequest`.
3. Handler/pipeline evaluates capability + constraints + mapping.
4. Allowed request is dispatched through connector.
5. Response and audit event are emitted.

### 4.3 HTTPS path via CONNECT

At CONNECT handshake:

- sidecar evaluates decision on `host:port` and emits audit outcome.

If allowed:

- host matches MITM interception scope: sidecar performs TLS termination, inspects decrypted HTTP request, enforces L7 policy, then re-encrypts upstream.
- host outside interception scope (or bypassed): sidecar creates a blind TCP tunnel and enforces only CONNECT-level policy.

## 5. Security Model and Invariants

### 5.1 Core invariants

- Fail-closed by default on invalid/unsafe conditions.
- No silent direct egress fallback from sidecar startup failure in fail-closed mode.
- In Linux structural mode, DNS resolution is sandbox-local and cannot fall
  back to the host resolver.
- HTTPS interception is explicit and host-scoped.
- Strict hosts deny when MITM setup fails.

### 5.2 HTTPS MITM CA model

Sidecar uses local CA material to sign per-host leaf certificates for intercepted TLS sessions.

Current behavior:

- if CA cert/key are both absent, sidecar performs first-run local generation,
- if any CA artifact exists, sidecar must load that exact CA state or fail startup,
- if CA cert exists but key is missing, startup fails,
- if CA key exists but cert is missing, startup fails,
- if CA cert/key are malformed, unreadable, or do not match, startup fails,
- on Unix, key permissions are enforced as owner-only (`0600`).

Sidecar must never regenerate or repair CA material after initialization has
observed existing CA state. Partial or malformed state is treated as a hard
startup error to avoid implicit trust reset.

No external certificate service dependency is required.

### 5.3 Host pattern hardening

Wildcard controls are DNS-label-aware and intentionally restricted.

Allowed forms:

- `*`
- exact host (`api.openai.com`)
- leading subdomain wildcard (`*.example.com`)

Rejected forms:

- mid-pattern wildcard (`api.*.com`)
- prefix wildcard without label boundary (`*openai.com`)
- top-level wildcard scope (`*.com`)

## 6. Configuration Surfaces

Main configuration reference:

- `docs/configuration.md`

Important fields:

- `[interceptor]`
  - `mode`
  - `listen_addr`
  - `max_request_body_bytes`
- `[interceptor.connect_relay]`
  - `setup_timeout` (default 10)
  - `session_max` (default 600)
- `[interceptor.https_mitm]`
  - `enabled` (default true)
  - `intercept_hosts`
  - `bypass_hosts`
  - `strict_hosts`
  - `ca_cert_path` / `ca_key_path`
  - `cert_ttl`
  - `cert_cache_capacity`
- `[ca]`
  - `dir`

## 7. Behavior Matrix

| Traffic type         | Visibility                   | Enforcement level     | Typical usage                  |
| -------------------- | ---------------------------- | --------------------- | ------------------------------ |
| HTTP                 | Full request                 | L7 method/path/action | plain HTTP targets             |
| HTTPS CONNECT tunnel | Handshake (`host:port`) only | destination-level     | non-intercepted/bypassed hosts |
| HTTPS MITM           | Full decrypted request       | L7 method/path/action | managed/intercepted HTTPS APIs |

## 8. Performance Characteristics

Current implementation choices:

- cached per-host TLS acceptors (bounded cache + TTL),
- bounded request body reads,
- bounded CONNECT/MITM setup timeout,
- bounded CONNECT/MITM session max lifetime.

Known hotspots for benchmark phase:

- cert cache lock contention under high host cardinality,
- cache order maintenance cost at high churn,
- memory overhead from buffered request bodies,
- task-per-connection pressure at high concurrency.

## 9. Testing and Validation Status

Covered in sidecar tests:

- CONNECT allow/deny behavior,
- MITM L7 policy path,
- strict host fail-closed preflight behavior,
- CA generation and key permission checks,
- CA cert/key coherence checks,
- wildcard validation and matcher behavior,
- request body limits for HTTP and MITM-decrypted HTTPS.

E2E harness currently validates:

- runtime launch + sidecar routing,
- audit emission,
- fail-closed behavior when sidecar is unavailable,
- HTTPS connectivity checks.

## 10. Current Known Gaps

1. Trust bootstrap is not yet fully standardized in `firma-run` for all client ecosystems (curl/Python/Node/Java/Go).
2. Full HTTPS L7 E2E matrix across profiles and runtimes remains to be completed.
3. Metrics for MITM/cache/tunnel internals can be expanded for stronger observability and benchmark precision.
4. Cross-OS confinement parity is not yet equivalent to Linux structural mode.

## 11. Operational Guidance

### 11.1 Safe defaults

- Keep MITM scoped to intended hosts.
- Use `strict_hosts` for high-assurance targets.
- Keep CA key local and secret.
- Do not commit generated CA artifacts.

### 11.2 Compatibility expectations

- Clients without sidecar CA trust will fail TLS handshake for MITM hosts (expected behavior).
- Certificate-pinned clients are expected to fail under generic MITM unless explicitly bypassed.

### 11.3 Rollback controls

If interoperability issues occur:

1. narrow `intercept_hosts` scope, or
2. move problematic endpoints into `bypass_hosts`, or
3. disable MITM (`enabled = false`) temporarily.

## 12. References

- [FIR-61 Deep Dive](./fir-61-firma-run-deep-dive.md)
- [FIR-63 HTTPS MITM Deep Dive](./fir-63-https-mitm-deep-dive.md)
- [Sidecar Overview](./sidecar-overview.md)
- [Configuration Reference](../configuration.md)
- [Firma Run Local Testing](../../examples/firma-run/local/docs/local-testing.md)
