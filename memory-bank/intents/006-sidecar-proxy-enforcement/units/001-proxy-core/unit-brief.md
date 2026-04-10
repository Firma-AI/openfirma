---
unit: 001-proxy-core
intent: 006-sidecar-proxy-enforcement
phase: inception
status: draft
created: 2026-04-05T12:00:00Z
updated: 2026-04-05T12:00:00Z
---

# Unit Brief: Proxy Core

## Purpose

Implement the Pingora-based HTTP/HTTPS proxy that intercepts all agent outbound traffic, performs TLS MITM for HTTPS, manages configuration and startup lifecycle, and serves as the integration backbone that wires all other units into the request/response pipeline.

## Scope

### In Scope

- Pingora `ProxyHttp` implementation with request/response lifecycle hooks
- Plain HTTP request interception (method, headers, body, URL available for enforcement)
- HTTPS CONNECT tunnel handling with MITM TLS interception
- Dynamic certificate generation (rcgen) signed by Sidecar-managed CA
- Domain-scoped cert caching (no duplicate generation for concurrent requests)
- CA keypair generation on first run, persistence, and reuse across restarts
- TOML configuration file parsing with CLI argument overrides
- `/healthz` and `/readyz` health/readiness endpoints
- Graceful SIGTERM shutdown: stop new connections, drain in-flight, flush audit, exit
- Firma-specific JSON denial response format for proxy-path denials (403/400/503)
- Fail-fast on invalid config or malformed policy at startup

### Out of Scope

- Enforcement logic (owned by 002-enforcement-pipeline)
- Policy/revocation loading (owned by 003-policy-revocation)
- LLM response parsing (owned by 004-llm-response-parser)
- Credential injection (owned by 005-connector-credentials)
- Audit event emission (owned by 006-audit-observability)

---

## Assigned Requirements

| FR | Requirement | Priority |
|----|-------------|----------|
| FR-1 | HTTP/HTTPS Proxy Interceptor (Pingora) | Must |
| FR-11 | HTTP Proxy Response Format | Must |
| FR-12 | Configuration & Startup | Must |

---

## Domain Concepts

### Key Entities

| Entity | Description | Attributes |
|--------|-------------|------------|
| ProxyServer | Pingora server instance | listen_addr, tls_config, shutdown_timeout |
| CertCache | Domain-scoped certificate cache | domain → (cert, key), TTL |
| CaKeypair | Sidecar CA certificate + private key | cert_pem, key_pem, path |
| SidecarConfig | Parsed TOML configuration | listen_addr, policy_dir, authority_url, log_level, drain_timeout |
| DenialResponse | Firma JSON denial body | firma_decision, reason, detail, request_id, timestamp |

### Key Operations

| Operation | Description | Inputs | Outputs |
|-----------|-------------|--------|---------|
| intercept_request | Capture HTTP request for enforcement | Raw HTTP request | ExecutionEnvelope (via enforcement pipeline) |
| mitm_connect | Handle HTTPS CONNECT with dynamic cert | CONNECT request, target host | TLS-terminated connection |
| generate_cert | Create domain-specific cert signed by CA | domain, CA keypair | (cert, key) pair |
| format_denial | Build Firma JSON denial response | reason_code, detail | HTTP response (403/400/503) |
| check_readiness | Evaluate readiness conditions | Policy loaded, CA available, creds initialized | 200 or 503 |

---

## Story Summary

| Metric | Count |
|--------|-------|
| Total Stories | 6 |
| Must Have | 6 |
| Should Have | 0 |
| Could Have | 0 |

### Stories

| Story ID | Title | Priority | Status |
|----------|-------|----------|--------|
| 001-http-proxy-listener | Plain HTTP proxy interception | Must | Planned |
| 002-https-mitm-interception | HTTPS CONNECT + TLS MITM | Must | Planned |
| 003-ca-keypair-management | CA keypair generation and persistence | Must | Planned |
| 004-proxy-denial-response-format | Firma JSON denial responses | Must | Planned |
| 005-config-and-startup | TOML config + CLI overrides + fail-fast | Must | Planned |
| 006-health-readiness-shutdown | Health, readiness, graceful shutdown | Must | Planned |

---

## Dependencies

### Depends On

| Unit | Reason |
|------|--------|
| None | Foundational transport layer |

### Depended By

| Unit | Reason |
|------|--------|
| All other units | Proxy-core lifecycle hooks integrate enforcement, parsing, connector, audit |

### External Dependencies

| System | Purpose | Risk |
|--------|---------|------|
| Pingora | HTTP proxy engine | Medium — sparse documentation, lifecycle hook ordering critical |
| rcgen | Dynamic cert generation | Low — well-tested crate |
| rustls | TLS implementation | Low — mature crate |

---

## Technical Context

### Suggested Technology

- Pingora `ProxyHttp` trait for proxy lifecycle
- rcgen for certificate generation
- rustls + tokio-rustls for TLS termination
- toml crate for config parsing
- clap for CLI argument parsing

### Integration Points

| Integration | Type | Protocol |
|-------------|------|----------|
| AI Agent | Proxy client | HTTP/HTTPS (HTTP_PROXY) |
| Enforcement Pipeline | Internal | Rust trait calls |
| Connector | Internal | Rust trait calls |
| Audit Emitter | Internal | Async channel |

---

## Constraints

- Must use Pingora as proxy engine (tech stack decision)
- Must use rustls + rcgen (no OpenSSL dependency)
- CA keypair must persist across restarts
- Drain timeout must be configurable (default 30s)
- Readiness requires: policy bundle loaded + CA available + credential providers initialized

---

## Success Criteria

### Functional

- [ ] Plain HTTP requests intercepted with full request available
- [ ] HTTPS CONNECT triggers dynamic cert gen, agent receives valid TLS
- [ ] CA keypair generated on first run, reused on restarts
- [ ] Denial responses follow Firma JSON schema with correct status codes
- [ ] TOML config loaded with CLI overrides
- [ ] /healthz and /readyz return correct status
- [ ] SIGTERM triggers graceful shutdown with drain

### Non-Functional

- [ ] End-to-end enforcement overhead < 3ms p95
- [ ] Concurrent HTTPS requests to same domain share cached cert
- [ ] Invalid config at startup causes fail-fast with clear error

### Quality

- [ ] Integration tests exercising full Pingora request/response lifecycle
- [ ] Concurrent cert generation tests
- [ ] All acceptance criteria from FR-1, FR-11, FR-12 met

---

## Bolt Suggestions

| Bolt | Type | Stories | Objective |
|------|------|---------|-----------|
| 006-proxy-core | DDD | 001, 002, 003 | HTTP/HTTPS proxy transport + TLS MITM + CA management |
| 007-proxy-core | DDD | 004, 005, 006 | Denial responses + config/startup + health/shutdown |

---

## Notes

- Pingora lifecycle hook ordering is a high-risk area — spike early if needed
- Proxy-core is the integration backbone; its lifecycle hooks are where all other units plug in
- The proxy itself does not make enforcement decisions — it delegates to the enforcement pipeline
