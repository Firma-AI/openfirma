# mTLS Playbook: Authority ↔ Sidecar

Each Sidecar presents a client certificate during the mutual TLS (mTLS)
handshake. The Authority verifies the certificate chain and checks the client
identity against a configurable allow-list. Connections from unknown Sidecars
are dropped at the TLS handshake, before any gRPC frame is processed.

Scope note: this playbook applies to configured `https://` Authority deployments. The `firma run --authority local` autostart path is a developer convenience mode on loopback `http://` and does not enable mTLS.

## Security properties

- **Sidecar authentication.** The Authority cryptographically identifies each connecting Sidecar by its client certificate CN or DNS SAN. Spoofed or unknown clients are rejected before any policy data is exchanged.
- **Allow-list enforcement.** Even a cert signed by the trusted CA is rejected if its identity is not present in `authorized_clients_path`. Revoking a Sidecar requires only removing it from the allow-list and reloading the Authority.
- **Handshake-level rejection.** Unauthorized clients never reach gRPC — the TLS connection is aborted during the handshake, not via a gRPC `PERMISSION_DENIED` response.

## Certificate hierarchy

```
Firma mTLS Client CA
├── sidecar-production-1.internal (Sidecar A client cert)
├── sidecar-production-2.internal (Sidecar B client cert)
└── sidecar-staging.internal      (Staging Sidecar client cert)
```

The CA cert is distributed to the Authority (`mtls_client_ca_cert_path`). Keep the CA key offline after signing.

## Step-by-step setup

### 1. Generate the client CA

Run this once per deployment environment. Keep the CA key offline after signing is complete.

```bash
firma authority --config firma.toml generate-client-ca \
  --cert-out firma-client-ca.crt \
  --key-out  firma-client-ca.key \
  --cn       "Firma mTLS Client CA"
```

Set the paths in the Authority section of `firma.toml`:

```toml
[authority]
# Server TLS (required for mTLS)
tls_cert_path = "/etc/firma/authority.crt"
tls_key_path = "/etc/firma/authority.key"

# Client authentication
mtls_client_ca_cert_path = "/etc/firma/firma-client-ca.crt"
mtls_client_ca_key_path = "/etc/firma/firma-client-ca.key" # for issue-client-cert only
authorized_clients_path = "/etc/firma/authorized_clients.toml"
```

### 2. Create the authorized-clients allow-list

```toml
# /etc/firma/authorized_clients.toml
# One entry per Sidecar. The identity must match the CN or DNS SAN
# of the Sidecar's client certificate.

[[clients]]
identity = "sidecar-production-1.internal"

[[clients]]
identity = "sidecar-staging.internal"
```

The file accepts only `[[clients]]` tables with an `identity` field. Unknown
tables or fields fail Authority startup.

Restart the Authority after modifying this file (it is read once at startup).

### 3. Issue a client certificate for each Sidecar

```bash
firma authority --config firma.toml issue-client-cert \
  --cn      "sidecar-production-1.internal" \
  --san     "sidecar-production-1.internal" \
  --days    365 \
  --cert-out sidecar-production-1.crt \
  --key-out  sidecar-production-1.key
```

The command prints the identity string you need to add to `authorized_clients.toml`.

### 4. Configure the Sidecar

Add the Sidecar client settings to the same `firma.toml`:

```toml
[sidecar.authority]
url = "https://authority.internal:50051"
ca_cert_path = "/etc/firma/authority-ca.crt" # server CA
tls_client_cert_path = "/etc/firma/sidecar.crt" # client cert
tls_client_key_path = "/etc/firma/sidecar.key" # client key
```

Both `tls_client_cert_path` and `tls_client_key_path` must be set together or both omitted.

### 5. Distribute the server CA to Sidecars

Copy the Authority's server CA cert (not the client CA cert) to every Sidecar host at the path configured in `ca_cert_path`.

```bash
scp authority-ca.crt sidecar-host:/etc/firma/authority-ca.crt
```

## Certificate rotation

### Rotate a Sidecar client certificate

1. Issue a new cert with `firma authority issue-client-cert` (same CN/SAN).
2. Deploy the new cert and key to the Sidecar host.
3. Restart the Sidecar.

The old cert continues to work until the Authority is restarted with the new allow-list — or until the old cert expires.

### Rotate the client CA

Add the new CA cert to `mtls_client_ca_cert_path` as a PEM bundle (concatenate old + new), before revoking the old CA:

1. Generate a new client CA with `generate-client-ca`.
2. Issue new client certs for all Sidecars.
3. Concatenate old and new CA certs into the `mtls_client_ca_cert_path` file.
4. Restart the Authority.
5. Roll out new Sidecar client certs + restart Sidecars.
6. Once all Sidecars use the new CA, remove the old CA from the bundle and restart the Authority.

### Rotate the Authority server TLS certificate

See [transport.md](transport.md#certificate-rotation) — server cert rotation is independent of mTLS.

## Revoking a Sidecar

1. Remove the Sidecar's entry from `authorized_clients.toml`.
2. Restart the Authority.

The revoked Sidecar's next reconnect attempt will be rejected at the TLS handshake. Any existing connection is torn down when the Sidecar reconnects (e.g. after its next policy stream disconnect).

For immediate disconnection, restart the Authority; this terminates all active connections.

Authority-side mTLS enforces revocation operationally through allow-list updates
(`authorized_clients.toml`) and certificate rotation or expiry. The TLS verifier
does not fetch CRLs or perform OCSP checks.

## Failure modes

| Condition                                                                                       | Behavior                                                                                                  |
| ----------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| Client cert signed by unknown CA                                                                | TLS handshake rejected (chain validation fails); Sidecar stays `policy_bundle_ready = false`; fail-closed |
| Client CN/SAN not in allow-list                                                                 | TLS handshake rejected after chain validation; same fail-closed behavior                                  |
| Client presents no cert                                                                         | TLS handshake rejected (`client_auth_mandatory = true`); fail-closed                                      |
| `authorized_clients_path` missing at startup                                                    | Authority exits at startup with an error                                                                  |
| `authorized_clients_path` is empty (no entries)                                                 | Authority starts, but all clients are rejected                                                            |
| Server cert missing/invalid at startup                                                          | Authority exits at startup                                                                                |
| Wrong server CA on Sidecar                                                                      | Server TLS verification fails                                                                             |
| Client cert is PKI-revoked by CRL/OCSP only (still signed by trusted CA and still allow-listed) | No automatic rejection; remove the identity from the allow-list to revoke access                          |
| Both `tls_client_cert_path`/`tls_client_key_path` set without the other                         | Sidecar config validation rejects startup                                                                 |
| `mtls_client_ca_cert_path` set without TLS server cert                                          | Authority exits at startup with a validation error                                                        |

## Allow-list file format reference

```toml
# /etc/firma/authorized_clients.toml

[[clients]]
identity = "sidecar-production-1.internal" # Must match DNS SAN (preferred) or CN

[[clients]]
identity = "sidecar-production-2.internal"

[[clients]]
identity = "sidecar-staging"
```

**Identity resolution order** (consistent between Authority verifier and `issue-client-cert`):

1. First DNS SAN in the certificate's Subject Alternative Name extension.
2. Common Name (CN) from the Subject Distinguished Name — used only when no DNS SAN is present.

Always set a DNS SAN on new certs to make identity unambiguous. Use `--san` with `issue-client-cert`.
