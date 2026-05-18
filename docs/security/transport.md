# Authority ↔ Sidecar Transport Security

The Authority ↔ Sidecar gRPC channel carries the policy bundle stream and revocation stream — both of which control what every Sidecar accepts as a valid capability. This document covers V1 TLS server-only mode: how to generate certificates, how to configure both sides, and what to expect in failure cases.

## What V1 achieves

- **Encrypted in transit.** Policy bundles and revocation events over the LAN are confidential and integrity-protected.
- **Authority authentication.** Each Sidecar verifies the Authority's certificate against a configured CA. A MitM serving a spoofed policy bundle is rejected at the TLS handshake.
- **Capability tokens are unaffected.** PASETO v4 signing/verification is independent of transport.

## What V1 does NOT achieve

Sidecar identity is not asserted — anyone who can establish a TLS connection to the Authority's gRPC endpoint can call `IssueCapability`. V1 mitigation is operational: restrict network access via VPN, security groups, or a mesh VPN. Closing this gap is V1.1 mTLS.

## Configuration

## One-shot bootstrap (local/dev)

For local development, you can generate a CA + Authority server certs in one
command:

```bash
firma authority init-tls --out-dir /tmp/firma-tls --host localhost --host 127.0.0.1
```

This writes:

- `authority-ca.crt` / `authority-ca.key`
- `authority.crt` / `authority.key`

Then wire the generated paths into Authority + Sidecar config.

### Authority (`firma-authority.toml`)

```toml
# Path to the server's TLS certificate (PEM).
tls_cert_path = "/etc/firma/authority.crt"

# Path to the server's TLS private key (PEM).
tls_key_path  = "/etc/firma/authority.key"
```

Both fields must be set together or neither. When set, the gRPC listener becomes TLS-only.

### Sidecar (`firma-sidecar.toml`)

```toml
[policy]
authority_url = "https://authority.internal:50051"

[authority]
ca_cert_path = "/etc/firma/authority-ca.crt"
# Optional and strongly discouraged: only for explicit non-loopback
# plaintext authority in temporary/dev environments.
allow_insecure_remote_authority = false
```

`authority.ca_cert_path` is required when `policy.authority_url` uses `https://`.
For `http://`, sidecar permits loopback (`localhost`, `127.0.0.1`, `::1`) by
default for local dev. Non-loopback `http://` is rejected unless
`authority.allow_insecure_remote_authority = true`.

## Certificate paths

### Self-signed (dev / single-node)

Generate a CA and a server certificate signed by it. Keep the CA key offline after signing.

```bash
# 1. CA key + self-signed CA cert
openssl genrsa -out authority-ca.key 4096
openssl req -x509 -new -nodes \
  -key authority-ca.key \
  -sha256 -days 3650 \
  -subj "/CN=Firma Authority CA" \
  -out authority-ca.crt

# 2. Server key + CSR
openssl genrsa -out authority.key 2048
openssl req -new \
  -key authority.key \
  -subj "/CN=authority.internal" \
  -out authority.csr

# 3. SAN extension file
cat > authority.ext <<EOF
subjectAltName = DNS:authority.internal, DNS:localhost
EOF

# 4. Sign the server cert with the CA
openssl x509 -req \
  -in authority.csr \
  -CA authority-ca.crt -CAkey authority-ca.key -CAcreateserial \
  -extfile authority.ext \
  -days 365 -sha256 \
  -out authority.crt
```

Distribute `authority-ca.crt` to every Sidecar host. Keep `authority-ca.key` offline.

Authority config:
```toml
tls_cert_path = "./authority.crt"
tls_key_path  = "./authority.key"
```

Sidecar config:
```toml
[authority]
ca_cert_path = "./authority-ca.crt"
```

### Internal CA (team / staging)

Request a certificate from your internal CA for the hostname the Authority listens on. The Subject Alternative Name must include the hostname (or IP) that Sidecars use in `authority_url`.

Distribute the internal CA bundle (or the issuing intermediate CA cert) to Sidecars as `ca_cert_path`.

## Failure modes

| Condition | Behavior |
|-----------|----------|
| TLS cert mismatch (wrong CA) | Handshake rejected; policy bundle stream never connects; `policy_bundle_ready` stays `false`; Sidecar denies all requests (fail-closed) |
| CA cert file missing at sidecar startup | `build_channel` returns an error; sidecar process exits at startup |
| Both `tls_cert_path`/`tls_key_path` present, file unreadable | Authority `try_new` returns an error; authority process exits at startup |
| Only one of `tls_cert_path`/`tls_key_path` set | Authority `try_new` returns an error at startup |
| `https://` URL without `ca_cert_path` | Config validation rejects the config at sidecar startup |
| Non-loopback `http://` URL without `allow_insecure_remote_authority = true` | Config validation rejects startup (secure-by-default downgrade protection) |

## Certificate rotation

1. Generate a new server cert signed by the same CA.
2. Update `tls_cert_path` / `tls_key_path` on the Authority and restart.
3. Sidecars reconnect automatically (exponential backoff). No Sidecar config change needed as long as the CA is unchanged.

To rotate the CA itself, add the new CA cert to `ca_cert_path` as a PEM bundle (concatenate old and new CA certs) before revoking the old CA. Then complete the rotation after all Sidecars reload.
