---
id: 003-credential-injection
unit: 005-connector-credentials
intent: 006-sidecar-proxy-enforcement
status: draft
priority: must
created: 2026-04-05T12:00:00Z
assigned_bolt: null
implemented: false
---

# Story: 003-credential-injection

## User Story

**As the** Sidecar
**I want** to derive a transport-ready execution view with injected credentials so that the agent never handles or sees target-system secrets
**So that** credential isolation is enforced at the infrastructure level, eliminating credential leakage through agent code

## Acceptance Criteria

- [ ] **Given** an authorized (Stage 2 ALLOW) immutable ExecutionEnvelope and resolved credentials, **When** the credential injection layer runs, **Then** a transport-ready execution view is derived from the envelope without mutating the original ExecutionEnvelope
- [ ] **Given** a derived transport-ready execution view with Bearer token credentials, **When** the view is inspected, **Then** the `Authorization: Bearer {token}` header is present in the outbound request headers
- [ ] **Given** a derived transport-ready execution view with custom header credentials, **When** the view is inspected, **Then** the specified custom header and value are present in the outbound request headers
- [ ] **Given** a derived transport-ready execution view with query parameter credentials, **When** the view is inspected, **Then** the specified query parameter and value are appended to the outbound request URL
- [ ] **Given** credentials are injected into the transport view and the target responds, **When** the response is returned to the agent, **Then** the agent never sees the injected credentials in the request echo, response headers, or any Sidecar-generated metadata
- [ ] **Given** the CredentialProvider returns an error during credential resolution, **When** the injection layer processes the envelope, **Then** the result is `DENY: CREDENTIAL_INJECTION_FAILED` and no outbound request is dispatched (fail-closed)

## Technical Notes

- The `TransportView` is a new struct that holds a reference (or owned copy of relevant fields) from the ExecutionEnvelope plus the injected credentials applied to the outbound request representation
- The ExecutionEnvelope's immutability is enforced by Rust's ownership model: private fields, no `&mut` accessors, consumed by the builder. The transport view is a separate struct, not a modified envelope
- TransportView construction (approximate):
  ```rust
  pub struct TransportView {
      pub method: Method,
      pub url: Url,
      pub headers: HeaderMap,  // includes injected credential headers
      pub body: Option<Bytes>,
  }
  ```
- The injection layer sits between Stage 2 ALLOW and the HTTP connector (story 001):
  `Stage 2 ALLOW -> CredentialProvider::resolve() -> derive TransportView -> HttpConnector::dispatch()`
- If the ExecutionEnvelope's original request already contains an `Authorization` header (agent-supplied), the injected credential should **replace** it (Sidecar-managed credentials take precedence over agent-supplied ones)
- For query parameter injection, ensure proper URL encoding of the parameter value
- The `DENY: CREDENTIAL_INJECTION_FAILED` response uses the standard Firma denial response format (FR-11) and emits an audit event
- Credential values must never appear in logs, error messages, or audit events — use `secrecy::SecretString` and redact in Display/Debug impls

## Dependencies

### Requires

- 002-credential-provider-trait (provides resolved Credentials for the target)

### Enables

- 001-http-connector (receives the TransportView for outbound dispatch)
- 006-audit-observability (CREDENTIAL_INJECTION_FAILED events emitted on failure)

## Edge Cases

| Scenario | Expected Behavior |
| -------- | ----------------- |
| No credentials configured for the target host | TransportView derived without credential injection; request dispatched as-is |
| Agent-supplied Authorization header present and Sidecar credential configured | Sidecar credential replaces the agent-supplied header (Sidecar takes precedence) |
| CredentialProvider returns an error (env var missing, config error) | DENY: CREDENTIAL_INJECTION_FAILED; no request dispatched; audit event emitted |
| Multiple credential types for the same target (e.g., Bearer + custom header) | Both applied to the TransportView; config supports multiple injection directives per target |
| Query parameter injection on a URL that already has query parameters | New parameter appended with `&`; existing parameters preserved |
| Credential value contains characters requiring URL encoding (query param injection) | Value is percent-encoded before appending to URL |
| ExecutionEnvelope is accessed after TransportView creation | Envelope remains available and unmodified (immutable, not consumed) |
| Concurrent requests to the same target with credentials | Each derives its own TransportView independently; no shared mutable state |
| Credential value is extremely long (>8KB header) | Injected as-is; target may reject with 431 (Request Header Fields Too Large); no connector-level validation |

## Out of Scope

- Credential rotation or refresh during injection (credentials are resolved once per request)
- Response scrubbing to remove credential echoes from target responses (target should not echo credentials; if it does, that is a target misconfiguration)
- Encrypting credentials in transit beyond TLS (TLS to target provides transport encryption)
- Credential auditing (the audit event records that credentials were injected but never the credential values)
- Dynamic credential providers (Vault, AWS Secrets Manager) — V1 is config-based only via CredentialProvider trait
