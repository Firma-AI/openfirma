---
id: 003-ca-keypair-management
unit: 001-proxy-core
intent: 006-sidecar-proxy-enforcement
status: draft
priority: must
created: 2026-04-05T12:00:00Z
assigned_bolt: null
implemented: false
---

# Story: 003-ca-keypair-management

## User Story

**As an** operator
**I want** the Sidecar to automatically generate and persist a CA keypair on first run so that I don't need to manually provision certificates
**So that** HTTPS interception works out of the box with minimal operational setup

## Acceptance Criteria

- [ ] **Given** the Sidecar starts for the first time with no existing CA keypair, **When** it initializes, **Then** it generates a new ECDSA P-256 (or P-384) CA certificate and private key using rcgen
- [ ] **Given** a newly generated CA keypair, **When** the Sidecar writes it to disk, **Then** the certificate is written to `{ca_dir}/firma-ca.crt` (PEM) and the private key to `{ca_dir}/firma-ca.key` (PEM) at a configurable path
- [ ] **Given** the Sidecar restarts and a CA keypair already exists at the configured path, **When** it initializes, **Then** it loads the existing keypair and does not generate a new one
- [ ] **Given** the CA certificate file, **When** an agent's runtime sets `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, or `SSL_CERT_FILE` to include this certificate, **Then** HTTPS connections through the proxy succeed without TLS errors
- [ ] **Given** the generated CA certificate, **When** inspected, **Then** it has the `CA:TRUE` basic constraint, `keyCertSign` key usage, a reasonable validity period (e.g., 10 years), and a distinguishable subject (e.g., `CN=Firma Sidecar CA`)

## Technical Notes

- Use `rcgen` to generate the CA certificate and private key
- Key algorithm: ECDSA with P-256 curve (fast generation, small key size, widely supported by rustls)
- The CA certificate must have `is_ca: true` in the basic constraints and `key_cert_sign` in key usage extensions — without these, rustls and other TLS libraries will reject certificates signed by it
- PEM encoding for both cert and key files for maximum interoperability
- File permissions: private key file should be written with mode `0600` (owner read/write only)
- The configurable path defaults to `./firma-ca/` or a platform-appropriate location (e.g., `$XDG_DATA_HOME/firma/ca/`)
- On startup, if the CA files exist but are malformed or unreadable, fail-fast with a clear error (do not silently regenerate)
- The CA keypair is also used by story 002 (HTTPS MITM) to sign dynamic per-domain certificates

## Dependencies

### Requires

- None (can be implemented independently; only rcgen is needed)

### Enables

- 002-https-mitm-interception (dynamic certs are signed by this CA keypair)
- 006-health-readiness-shutdown (readiness check requires CA to be available)

## Edge Cases

| Scenario | Expected Behavior |
| -------- | ----------------- |
| CA directory does not exist on first run | Create the directory (and parent directories) before writing files |
| CA key file exists but cert file is missing (or vice versa) | Fail-fast with clear error; do not regenerate partial state |
| CA files exist but are corrupted / not valid PEM | Fail-fast with clear error indicating the specific parsing failure |
| CA private key file has wrong permissions (world-readable) | Log a warning at startup; do not fail (operator's responsibility, but warn) |
| Disk is full or path is not writable | Fail-fast with clear OS-level error message |
| Operator provides a pre-existing CA keypair (e.g., enterprise CA) | Sidecar loads it from the configured path; no generation occurs; supports BYO-CA |
| CA certificate has expired (operator provided an old one) | Fail-fast with clear error indicating the CA cert is expired |

## Out of Scope

- Automatic CA certificate rotation (operator must manually rotate if needed)
- Distribution of the CA certificate to agents (operator responsibility via env vars or container image)
- Hardware security module (HSM) storage for the CA private key
- Certificate revocation list (CRL) or OCSP for the CA
