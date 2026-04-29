# Local Testing Guide

This guide shows how to test `firma run` locally without committing local secrets/config.

Verification reference:

- `docs/firma-run-verification-report.md` contains a full reproducible checklist and an example PASS/FAIL matrix from a successful run.

Latest verification snapshot (2026-04-26):

| Check                    | Expected                                                       | Observed                                                                                                                                   | Verdict | Notes                                                                                                                 |
| ------------------------ | -------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ | ------- | --------------------------------------------------------------------------------------------------------------------- |
| env/proxy wiring         | `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` + `FIRMA_RUN_*` present | `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY=http://127.0.0.1:18080`; `FIRMA_RUN_SANDBOX_ID`, `FIRMA_RUN_SESSION_ID`, runtime/bridge vars present | PASS    | `FIRMA_SIDECAR_*` not present in env output                                                                           |
| identity masking         | Non-root constrained identity                                  | `uid=1000(firma-user) gid=1000(firma-user)`; `whoami=firma-user`; passwd entry for `firma-user`                                            | PASS    |                                                                                                                       |
| bridge listener healthy  | Listener on `127.0.0.1:18080`                                  | `LISTEN ... 127.0.0.1:18080`                                                                                                               | PASS    | Initial `ss -ltn` attempt reported `Cannot open netlink socket: Operation not permitted`; elevated rerun succeeded    |
| bridge log clean/startup | Bridge log shows startup and no errors                         | `/tmp/firma-run/<sandbox_id>/proxy-bridge.log` exists and includes startup/ready entries                                                   | PASS    | If entries are missing, inspect `bwrap_entrypoint.sh` bridge bootstrap path                                           |
| HTTP proxied success     | status `200`, exit `0` via proxy path                          | `http status=200`, `http exit=0`                                                                                                           | PASS    |                                                                                                                       |
| HTTPS proxied success    | status `200`, exit `0` via proxy path                          | `https status=200`, `https exit=0`                                                                                                         | PASS    |                                                                                                                       |
| bypass blocked           | Direct egress (no proxy env) fails closed                      | `direct status=000`, `direct exit=7`                                                                                                       | PASS    | `curl: (7) Failed to connect to httpbin.org port 443`                                                                 |
| DNS confinement signal   | Local resolver confinement visible                             | `/etc/resolv.conf => nameserver 127.0.0.1`; `getent hosts localhost` works; `getent hosts httpbin.org` returns nothing                     | PASS    |                                                                                                                       |
| 5x HTTPS determinism     | 5/5 successful proxied HTTPS calls                             | Attempts `1-5` all `status=200`, each `exit=0`; times: `0.481664`, `0.465131`, `0.855019`, `0.543627`, `0.455090`                          | PASS    | Outer loop command exit was `1` because `[ -s /tmp/repeat.$i.err ]` was false (empty stderr), not due to curl failure |

Overall verdict: READY

## Why this guide

`firma run` local testing needs a sidecar config, mapping rules, and an audit signing key. Those are machine-local artifacts and should not be committed.

The repo now reserves `/.local/` for this purpose and ignores it in git.

## One-time bootstrap

From repo root:

```bash
scripts/firma-run-local-setup.sh
```

The script creates:

- `.local/mapping-rules.toml`
- `.local/firma_sidecar.local.toml`
- `.local/audit-key.pem`

Templates used:

- `docs/examples/firma-run/mapping-rules.local.example.toml`
- `docs/examples/firma-run/firma_sidecar.local.example.toml`

## Environment Variables

`firma run` supports the following environment variables to customize addresses and avoid port conflicts:

- `FIRMA_SIDECAR_ENDPOINT`: Sidecar endpoint (default: `tcp://127.0.0.1:8080`)
- `FIRMA_PROXY_LISTEN_ADDR`: Proxy bridge listen address (default: `127.0.0.1:18080`)
- `FIRMA_SIDECAR_CA_CERT_PATH`: Explicit path to sidecar MITM CA cert (preferred override)
- `FIRMA_SIDECAR_CA_DIR`: Directory containing `firma-ca.crt` (fallback override)

Example:

```bash
export FIRMA_SIDECAR_ENDPOINT=tcp://127.0.0.1:9090
export FIRMA_PROXY_LISTEN_ADDR=127.0.0.1:18181
cargo run -p firma-run -- run -- "your command"
```

When a sidecar MITM CA certificate is detected, `firma run` automatically exports trust env vars for common runtimes:

- `FIRMA_SIDECAR_CA_CERT_PATH`
- `REQUESTS_CA_BUNDLE`
- `SSL_CERT_FILE`
- `CURL_CA_BUNDLE`
- `NODE_EXTRA_CA_CERTS`
- `GIT_SSL_CAINFO`

This prevents `UnknownCA` failures for managed HTTPS MITM targets.

## Run sidecar + codex

Terminal A:

```bash
cargo run -p firma-sidecar -- -c .local/firma_sidecar.local.toml
```

Terminal B:

```bash
cargo run -p firma-run -- run --profile codex -- codex
```

Identity default:

- `firma run` defaults to sandbox identity masking mode (`sandbox_user`).
- Inside the sandbox, username/group labels are presented as `firma-user` while preserving host UID/GID compatibility for mounted workspace writes.

Compatibility override:

```bash
cargo run -p firma-run -- run --profile codex --preserve-host-user -- codex
```

Config override (`firma-run.yaml`):

```yaml
profiles:
  codex:
    identity_mode: host_user
```

Backend defaults by host OS:

- Linux: `bwrap`
- macOS: `vz`
- Windows: `wsl2`

Network-confinement defaults are backend-aware:

- `bwrap`: `enforce_network_namespace=true` (structural confinement path)
- `vz`/`wsl2`: `enforce_network_namespace=false` (proxy-mediated path)

If you explicitly set `enforce_network_namespace=true` with a non-`bwrap`
backend, `firma run` now fails at config validation with a clear error.

Manual backend override example:

```bash
cargo run -p firma-run -- run --backend vz --profile codex -- codex
```

## Run the local E2E harness

```bash
scripts/e2e-firma-run.sh
```

HTTPS CONNECT scenario:

```bash
scripts/e2e-firma-run.sh --https-check
```

Custom command example:

```bash
scripts/e2e-firma-run.sh --cmd 'cd example_agents/agents_sdk_py && curl -fsS --max-time 20 http://httpbin.org/get -o /dev/null'
```

Keep artifacts:

```bash
scripts/e2e-firma-run.sh --keep-artifacts
```

## Git safety rules

- `/.local/` is ignored by git.
- `.env` is ignored by git.
- Keep real API keys only in local files or local shell env.

## HTTPS behavior (current)

Sidecar supports both HTTPS modes:

1. TLS MITM mode (default for configured `intercept_hosts`): sidecar decrypts,
   normalizes, and enforces HTTPS requests at L7 (method/path/action class).
2. CONNECT tunnel mode (fallback for hosts outside `intercept_hosts` or explicit
   `bypass_hosts`): sidecar enforces/audits on `host:port`.

Important operational note:

- MITM requires agent trust for the sidecar CA (`firma-ca.crt`); if trust is
  not propagated into the runtime, TLS clients will fail handshake by design.
- For hosts in `strict_hosts`, MITM failures are fail-closed (no direct egress).

If proxied calls fail with `Failed to connect to 127.0.0.1:18080`, inspect bridge startup diagnostics:

```bash
ls -la /tmp/firma-run/<sandbox_id>/
sed -n '1,200p' /tmp/firma-run/<sandbox_id>/proxy-bridge.log
```

If DNS confinement behaves unexpectedly, inspect the sandbox-local DNS stub:

```bash
sed -n '1,200p' /tmp/firma-run/<sandbox_id>/dns-stub.log
```

In structural `bwrap` mode, `/etc/resolv.conf` points at `127.0.0.1`.
The V1 DNS stub intentionally refuses direct resolver queries so host ambient
DNS cannot become a bypass path; proxied HTTP/HTTPS traffic still carries
hostnames through the sidecar path.

## CONNECT implementation note

Why this exists:

1. Pingora defaults to rejecting CONNECT with `405 Method Not Allowed` unless CONNECT proxying is explicitly enabled.
2. In E2E runs, enabling that switch still yielded `502 Bad Gateway` for real HTTPS CONNECT targets in our flow.

What was changed:

1. Sidecar now handles CONNECT tunnel lifecycle explicitly in the HTTP interceptor runtime.
2. The handshake (`host:port`) is still enforced and audited before tunnel establishment.
3. Optional TLS MITM interception is available for configured hosts.
