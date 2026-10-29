# Authority ↔ Sidecar Transport Security

The Authority ↔ Sidecar gRPC channel carries the policy bundle stream and revocation stream — both of which control what every Sidecar accepts as a valid capability. This document covers V1 TLS server-only mode: how to generate certificates, how to configure both sides, and what to expect in failure cases.

## What V1 achieves

- **Encrypted in transit.** Policy bundles and revocation events over the LAN are confidential and integrity-protected.
- **Authority authentication.** Each Sidecar verifies the Authority's certificate against a configured CA, or against the platform's trusted roots when none is configured. A MitM serving a spoofed policy bundle is rejected at the TLS handshake.
- **Capability tokens are unaffected.** PASETO v4 signing/verification is independent of transport.

## Sidecar authentication

OpenFirma can present pre-shared-key credentials on Authority RPCs when the
Sidecar config includes `[sidecar.authority.credentials]`. The Sidecar sends `workspace_id`,
`sidecar_id`, and the resolved PSK on `IssueCapability`, `WatchPolicyBundle`,
and `WatchRevocations`.

If credentials are absent, OpenFirma sends no credentials. This keeps the local
Mini Authority development loop keyless. Remote deployments that require PSK
authentication should provision the key in the Authority operator workflow and
expose it to the Sidecar through either `pre_shared_key_env` or
`pre_shared_key_path`. A Sidecar serving one Firma Team run instead
presents that run's runtime credential as a bearer in request metadata
(`runtime_credential_env`), valid only while the run is live.

## What V1 does NOT achieve

TLS server verification alone does not assert Sidecar identity. Use PSK
credentials when the Authority enforces Sidecar authentication. mTLS remains an
orthogonal transport-hardening option for deployments that require client
certificate identity.

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

Then wire the generated paths into the Authority and Sidecar sections of one
`firma.toml`:

```toml
[authority]
# Path to the server's TLS certificate (PEM).
tls_cert_path = "/etc/firma/authority.crt"

# Path to the server's TLS private key (PEM).
tls_key_path = "/etc/firma/authority.key"

[sidecar.authority]
url = "https://authority.internal:50051"
ca_cert_paths = ["/etc/firma/authority-ca.crt"]
# Optional and strongly discouraged: only for explicit non-loopback
# plaintext authority in temporary/dev environments.
allow_insecure_remote_authority = false
```

The Authority TLS fields must be set together or neither. When set, the gRPC
listener becomes TLS-only. When neither is set, the Authority serves the pair
`firma config` generated in the state directory
(`<state_dir>/tls/authority.crt` and `authority.key`) and refuses to start if it
is absent: plaintext is a decision, taken with `firma authority --no-tls`, not
what a missing certificate means. With `sidecar.authority.ca_cert_paths`, the
Sidecar trusts only those CAs, which is how a private CA is pinned; with
several, for a rotation or an Authority behind more than one issuer, the
Authority's certificate must be signed by any one of them. Without a CA named, an `https://` Authority is verified against the
platform's trusted roots (`SSL_CERT_FILE` and `SSL_CERT_DIR` replace them, so
set them in the Sidecar's environment only on purpose), so an Authority with a
publicly trusted certificate needs no TLS setting beyond its URL. The two are
never combined: a named CA switches the platform's roots off, and
`disable_platform_roots = true` refuses them even with no CA named, which the
Sidecar rejects at startup rather than trust nothing. A host with
no trusted roots fails closed at startup. An `https://` Authority on this host
(`localhost` or a loopback IP) needs a CA, from `ca_cert_paths` or the state
directory, because no public CA certifies a loopback name.

```toml
[sidecar.authority]
url = "https://authority.internal:50051"
# The old and the new CA during a rotation; the platform's roots are ignored.
ca_cert_paths = [
  "/etc/firma/authority-ca.crt",
  "/etc/firma/authority-ca-next.crt",
]
```

For `http://`, sidecar permits loopback (`localhost`, `127.0.0.1`, `::1`) by
default for local dev. Non-loopback `http://` is rejected unless
`sidecar.authority.allow_insecure_remote_authority = true`. When
`sidecar.authority.connect_addr` is set, its physical IP—not the logical URL host—is
used for this locality check. The URL still determines TLS SNI and certificate
identity for `https://` connections.

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

Unified `firma.toml`:

```toml
[authority]
tls_cert_path = "./authority.crt"
tls_key_path = "./authority.key"

[sidecar.authority]
url = "https://authority.internal:50051"
ca_cert_paths = ["./authority-ca.crt"]
```

### Internal CA (team / staging)

Request a certificate from your internal CA for the hostname the Authority listens on. The Subject Alternative Name must include the hostname (or IP) that Sidecars use in `sidecar.authority.url`.

Distribute the internal CA bundle (or the issuing intermediate CA cert) to Sidecars in `ca_cert_paths`.

## Failure modes

| Condition                                                                   | Behavior                                                                                                                                |
| --------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| TLS cert mismatch (wrong CA)                                                | Handshake rejected; policy bundle stream never connects; `policy_bundle_ready` stays `false`; Sidecar denies all requests (fail-closed) |
| A named CA file missing, not PEM, or holding no certificate                 | Sidecar startup and the `firma run` capability mint fail, naming the file                                                               |
| Both `tls_cert_path`/`tls_key_path` present, file unreadable                | Authority `try_new` returns an error; authority process exits at startup                                                                |
| Only one of `tls_cert_path`/`tls_key_path` set                              | Authority `try_new` returns an error at startup                                                                                         |
| `https://` URL with no CA named, certificate not trusted by the roots       | Handshake rejected; same fail-closed behavior as a wrong CA                                                                             |
| `disable_platform_roots = true` with no CA named                            | Config validation rejects the config at sidecar startup and in `firma run`                                                              |
| `https://` loopback URL with no CA named and no state-directory CA          | Config validation rejects the config at sidecar startup, naming the state-directory default                                             |
| Non-loopback `http://` URL without `allow_insecure_remote_authority = true` | Config validation rejects startup (secure-by-default downgrade protection)                                                              |

## Certificate rotation

1. Generate a new server cert signed by the same CA.
2. Update `tls_cert_path` / `tls_key_path` on the Authority and restart.
3. Sidecars reconnect automatically (exponential backoff). No Sidecar config change needed as long as the CA is unchanged.

To rotate the CA itself, name the new CA next to the old one in `ca_cert_paths`, as in the example above, before revoking the old CA; a PEM bundle in one file works too. Then complete the rotation after all Sidecars reload.
