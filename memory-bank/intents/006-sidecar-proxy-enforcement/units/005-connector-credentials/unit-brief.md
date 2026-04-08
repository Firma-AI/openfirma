---
unit: 005-connector-credentials
intent: 006-sidecar-proxy-enforcement
phase: inception
status: draft
created: 2026-04-05T12:00:00Z
updated: 2026-04-05T12:00:00Z
---

# Unit Brief: Connector & Credentials

## Purpose

Implement the outbound HTTP connector that dispatches authorized requests to target systems, and the credential injector that derives transport-ready execution views with injected credentials. The agent never handles target-system credentials.

## Scope

### In Scope

- Generic HTTP connector translating ExecutionEnvelope + derived view to outbound HTTP request
- Connection pooling with configurable pool size per target host
- Configurable per-target timeout (default 30s)
- ConnectorResponse with status code, headers, body, latency for audit
- `CONNECTOR_TIMEOUT` on timeout
- Connector boundary rules: does not inspect/modify intent, capability, or metadata fields
- `CredentialProvider` trait with config-based implementation
- Per-target credential mapping in configuration (target host → header name + value source)
- Credentials sourced from environment variables or config file values
- Supports `Authorization: Bearer {token}`, custom header injection, query parameter injection
- Transport-ready execution view derivation (ExecutionEnvelope never mutated)
- `DENY: CREDENTIAL_INJECTION_FAILED` on failure (fail-closed)
- Agent never sees injected credentials

### Out of Scope

- Enforcement decisions (owned by 002-enforcement-pipeline)
- Dynamic secret providers (Vault, AWS Secrets Manager) — V1 is config-based only
- Non-HTTP connectors

---

## Assigned Requirements

| FR | Requirement | Priority |
|----|-------------|----------|
| FR-8 | Generic HTTP Connector | Must |
| FR-9 | Credential Injector | Must |

---

## Domain Concepts

### Key Entities

| Entity | Description | Attributes |
|--------|-------------|------------|
| HttpConnector | Dispatches authorized HTTP requests | pool_size, timeout, target_host |
| ConnectorResponse | Response from target system | status_code, headers, body, latency_us |
| CredentialProvider | Trait for credential resolution | resolve(target) → Credentials |
| CredentialMapping | Per-target credential configuration | target_host, header_name, value_source (env/config) |
| TransportView | Derived execution view with credentials | ExecutionEnvelope ref + injected auth headers |

### Key Operations

| Operation | Description | Inputs | Outputs |
|-----------|-------------|--------|---------|
| dispatch | Send authorized request to target | TransportView | ConnectorResponse |
| resolve_credentials | Look up credentials for target | Target host, config | Credentials or Error |
| derive_transport_view | Build transport-ready view from envelope | ExecutionEnvelope, Credentials | TransportView |
| inject_credentials | Apply credentials to outbound request | Raw request, Credentials | Credentialed request |

---

## Story Summary

| Metric | Count |
|--------|-------|
| Total Stories | 3 |
| Must Have | 3 |
| Should Have | 0 |
| Could Have | 0 |

### Stories

| Story ID | Title | Priority | Status |
|----------|-------|----------|--------|
| 001-http-connector | Outbound dispatch, connection pooling, timeouts | Must | Planned |
| 002-credential-provider-trait | CredentialProvider trait + config-based implementation | Must | Planned |
| 003-credential-injection | Derive transport view, inject creds, fail-closed | Must | Planned |

---

## Dependencies

### Depends On

| Unit | Reason |
|------|--------|
| None | Independent outbound dispatch |

### Depended By

| Unit | Reason |
|------|--------|
| 001-proxy-core | Called after Stage 2 ALLOW to dispatch authorized requests |

### External Dependencies

| System | Purpose | Risk |
|--------|---------|------|
| reqwest or hyper | HTTP client | Low |

---

## Technical Context

### Suggested Technology

- hyper or reqwest for HTTP client (connection pooling built-in)
- tokio for async I/O

### Integration Points

| Integration | Type | Protocol |
|-------------|------|----------|
| Target APIs | External | HTTP/HTTPS |
| Enforcement Pipeline | Internal | Receives authorized ExecutionEnvelope |
| Proxy Core | Internal | Called from Pingora lifecycle |

---

## Constraints

- Connector does not inspect or modify intent, capability, or metadata fields (FEP §9)
- ExecutionEnvelope is never mutated — transport view is derived
- Agent must never see injected credentials in request or response
- Failed credential injection → DENY: CREDENTIAL_INJECTION_FAILED (fail-closed)
- V1: config-based credential injection only (no Vault/dynamic providers)

---

## Success Criteria

### Functional

- [ ] Authorized envelope translated to correct HTTP request
- [ ] Connection pooling with configurable pool size per host
- [ ] Per-target timeout with CONNECTOR_TIMEOUT on expiry
- [ ] Connector does not modify intent/capability/metadata fields
- [ ] Per-target credential mapping from configuration
- [ ] Credentials sourced from env vars and config values
- [ ] Bearer token, custom header, and query parameter injection supported
- [ ] Agent never sees credentials
- [ ] Failed injection → DENY: CREDENTIAL_INJECTION_FAILED

### Non-Functional

- [ ] Connection pooling reduces latency for repeated targets
- [ ] Timeout enforcement is reliable

### Quality

- [ ] Tests for all credential injection modes (Bearer, custom header, query param)
- [ ] Tests for failed injection (missing env var, bad config)
- [ ] Tests for connector timeout behavior

---

## Bolt Suggestions

| Bolt | Type | Stories | Objective |
|------|------|---------|-----------|
| 012-connector-credentials | DDD | 001, 002, 003 | HTTP connector + credential injection |

---

## Notes

- This is the simplest unit — well-understood HTTP client patterns
- The key design constraint is that the ExecutionEnvelope is immutable; credentials are applied via a derived transport view
- V1 scope is deliberately minimal (config-based only); the `CredentialProvider` trait exists for future extensibility
