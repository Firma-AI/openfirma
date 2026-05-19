# Security Policy

## Reporting a Vulnerability

Report security vulnerabilities to the maintainers via GitHub Security Advisories.
For critical issues, expect acknowledgment within 24 hours and a fix within 90 days.

**Do not** open public GitHub issues for security vulnerabilities.

## Supported Versions

Security updates are provided for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.x.y   | :white_check_mark: |

## Security Model

OpenFirma is a **runtime policy boundary for outbound agent traffic**. It answers the question: *should this agent be making this call right now?* — and records every decision in a tamper-evident audit log.

### What OpenFirma Covers

- **Capability validation (Stage 1):** Cryptographically verified PASETO v4 capability tokens prevent forged or tampered claims from reaching policy evaluation.
- **Policy enforcement (Stage 2):** Cedar-based runtime decisions on normalized action classes and resources.
- **Fail-closed behavior:** When the policy bundle is unavailable or the sidecar is under load, requests are denied.
- **Transport security:** TLS server-only mode for Authority ↔ Sidecar communication (mTLS planned for v1.1).

### What OpenFirma Does NOT Cover

OpenFirma is an L7/application-layer enforcement boundary, not a process containment layer. It does **not** prevent:

- Direct TCP/UDP connections from the agent
- Localhost/loopback traffic not routed through the Sidecar
- MCP over `stdio` or local process transports
- Generic gRPC hot-path traffic
- Local-only effects (shell, file I/O, subprocess, embedded SQLite)
- Native database wire protocols (PostgreSQL, MySQL, etc.)
- CVEs in sandbox backends (bwrap, vz, wsl2, firecracker)

For full coverage, agents must run inside `firma run` with `HTTP_PROXY` set. See the [threat model docs](docs-site/src/content/docs/concepts/threat-model.md) for the complete bypass map.

## Key Security Properties

### Fail-Closed
The Sidecar denies all requests when the policy bundle is unavailable, the capability is revoked, or the policy decision is `DENY`.

### Capability Tokens
PASETO v4 standalone signatures (Ed25519) are verified locally on every request. Tokens are selected internally by the Sidecar — agents never provide trusted claims directly.

### Transport Independence
Capability token signing/verification is independent of transport TLS. A valid token is required regardless of whether the Authority connection uses TLS.

### Audit Integrity
Audit events are signed with ECDSA P-256 off the hot path. For high-stakes deployments, use append-only sinks (WAL, gRPC ingestion) to prevent tampering with event absence.

## Configuration Security

### TLS (Authority ↔ Sidecar)

See [docs/security/transport.md](docs/security/transport.md) for certificate generation and configuration.

**Requirements for production:**
- Use a CA-issued certificate for the Authority; keep the CA key offline
- Distribute the CA certificate to every Sidecar host via `authority.ca_cert_path`
- Set `allow_insecure_remote_authority = false` (default) for all non-loopback connections
- V1 TLS is server-only; sidecar identity is **not** asserted (mTLS planned for v1.1)

### Policy Bundle Freshness

Configure `bundle_ttl_seconds` to suit your risk tolerance. Shorter TTLs mean faster revocation propagation but higher Authority load. Stale bundles result in fail-closed denials.

### Protected-by-Default

Set `mapping.default_protected = true` in production. Requests to unmapped hosts are PASSTHROUGH (no enforcement) when this is false.

### Credential Scoping

Scope each credential in `[credentials.*]` to a single host. Review these blocks as you would IAM grants.

## Known Limitations

### Resource Scope Matching (V1)

`CapabilityMap` currently uses prefix-based `resource_scope` matching. A token scoped to `api.openai.com` or `.../v1` may over-match `api.openai.com.evil.com/...` or `.../v1alpha`. A tighter host-boundary matcher is planned.

### Envelope Immutability

`ExecutionEnvelope` fields are not yet fully type-enforced as immutable. Post-construction mutation is an architectural convention rather than a compile-time guarantee.

### Session Metadata

`CapabilityMap::select()` does not yet use `session_id` for multi-agent scenarios. Caller-supplied `session_id` is written into emitted metadata. This is primarily an audit-correlation issue today.

### Timestamp Consistency

Stage 2 evaluates policy using a fresh `Utc::now()` rather than the normalized timestamp from the envelope. This is low severity but weakens replay/debug fidelity.

## Dependency Security

Run `cargo audit` to check for vulnerable dependencies in the Rust workspace. This project does not accept dependencies with known CVEs.

## Operational Security

### CA Private Key Exposure
If the MITM CA's private key leaks, anyone can sign certificates the Sidecar will trust. Treat the CA directory as immutable infrastructure; never regenerate it; never put it under version control.

### Authority Signing Key Compromise
If the Authority's Ed25519 signing key leaks, attackers can mint valid capability tokens. Key rotation requires re-issuing every active capability.

### Audit Log Tampering
Audit events are signed, but the Sidecar writes them before shipping to a durable sink. For high-stakes environments, use an append-only sink to detect deletion.

## Related Documentation

- [Threat model & bypasses](docs-site/src/content/docs/concepts/threat-model.md)
- [Transport security](docs/security/transport.md)
- [Interception boundary bypass analysis](docs/security/bypass-analysis.md)
- [Secure a coding agent guide](docs-site/src/content/docs/guides/secure-a-coding-agent.md)
- [Audit log guide](docs-site/src/content/docs/guides/audit-log.md)