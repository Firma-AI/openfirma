---
id: 002-https-mitm-interception
unit: 001-proxy-core
intent: 006-sidecar-proxy-enforcement
status: draft
priority: must
created: 2026-04-05T12:00:00Z
assigned_bolt: null
implemented: false
---

# Story: 002-https-mitm-interception

## User Story

**As an** AI agent runtime
**I want** my HTTPS connections to be transparently intercepted via MITM TLS so that encrypted traffic to LLM providers and APIs can be evaluated by enforcement
**So that** enforcement policies apply uniformly to both HTTP and HTTPS traffic without any bypass path

## Acceptance Criteria

- [ ] **Given** an agent sends an HTTPS request through the proxy, **When** the proxy receives the `CONNECT` method, **Then** it responds with `200 Connection Established` and initiates TLS termination with a dynamically generated certificate for the target domain
- [ ] **Given** a target domain (e.g., `api.openai.com`), **When** a dynamic certificate is generated, **Then** the certificate is signed by the Sidecar CA, has the target domain as the Common Name and Subject Alternative Name, and is valid for a reasonable TTL (e.g., 24 hours)
- [ ] **Given** concurrent HTTPS requests to the same domain, **When** they arrive simultaneously, **Then** only one certificate generation occurs and all requests share the cached certificate (no duplicate generation)
- [ ] **Given** an agent that trusts the Sidecar CA certificate, **When** it connects through the proxy to an HTTPS target, **Then** the TLS handshake succeeds and the agent receives a valid certificate chain
- [ ] **Given** the TLS-terminated connection, **When** the decrypted HTTP request is available, **Then** the full request (method, headers, body, URL) is accessible for enforcement, identical to plain HTTP interception
- [ ] **Given** the proxy uses rustls for TLS termination and rcgen for certificate generation, **When** building the sidecar, **Then** there is no OpenSSL dependency

## Technical Notes

- Pingora's CONNECT handling: intercept the `CONNECT` request in the appropriate `ProxyHttp` hook, establish a TLS server session with the agent using the dynamically generated cert, then read the inner HTTP request
- Use `rustls` with `tokio-rustls` for the TLS server-side (agent-facing) termination
- Use `rcgen` to generate X.509 certificates signed by the Sidecar CA keypair (story 003)
- Certificate cache should be a concurrent map (e.g., `DashMap<String, Arc<(CertifiedKey)>>`) keyed by domain
- For concurrent requests to the same domain, use a mechanism like `tokio::sync::OnceCell` per domain or a lock-per-key pattern to ensure only one generation runs
- The outbound connection to the actual target should use the system's default TLS (or rustls with the system CA bundle) — the MITM is only agent-facing
- After TLS termination, the inner HTTP request should flow through the same `request_filter` pipeline as plain HTTP (story 001)

## Dependencies

### Requires

- 001-http-proxy-listener (Pingora `ProxyHttp` implementation and request pipeline)
- 003-ca-keypair-management (CA keypair used to sign dynamic certificates)

### Enables

- All enforcement pipeline stories for HTTPS traffic (LLM provider calls are almost exclusively HTTPS)
- 004-llm-response-parser (response-path evaluation requires decrypted HTTPS responses)

## Edge Cases

| Scenario | Expected Behavior |
| -------- | ----------------- |
| Agent does not trust the Sidecar CA | TLS handshake fails on the agent side; proxy logs the failed connection; no request reaches enforcement |
| CONNECT to a non-standard port (e.g., `example.com:8443`) | Dynamic cert generated for `example.com`; port does not affect cert generation |
| CONNECT with IP address instead of hostname (e.g., `1.2.3.4:443`) | Dynamic cert generated with the IP as SAN (IP address type); verify rustls/rcgen support IP SANs |
| Target domain with wildcard or very long hostname | Certificate generated with the exact requested hostname; no wildcard issuance |
| Cert cache grows unbounded over long-running process | Implement TTL-based eviction or max-size cap on the cert cache |
| CA keypair is not yet available at CONNECT time | Reject the CONNECT with 503; this should only happen during startup race conditions |
| Agent sends data before TLS handshake completes | Standard TLS protocol handling; incomplete handshakes are cleaned up |
| Double CONNECT (CONNECT through a CONNECT tunnel) | Reject with 400; nested tunneling is not supported |

## Out of Scope

- CA keypair generation and persistence (story 003)
- Certificate revocation checking for upstream targets (the proxy trusts upstream CAs via system bundle)
- Client certificate authentication (mTLS) from agent to proxy
- Non-TLS tunneling (e.g., WebSocket upgrade through CONNECT)
