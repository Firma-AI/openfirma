# Local Testing Guide

This guide shows how to test `firma run` locally without committing local secrets/config.

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

Example:

```bash
export FIRMA_SIDECAR_ENDPOINT=tcp://127.0.0.1:9090
export FIRMA_PROXY_LISTEN_ADDR=127.0.0.1:18181
cargo run -p firma-run -- run -- "your command"
```

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

## Known limitation (current)

HTTPS `CONNECT` tunneling is supported for proxy routing and enforcement decisions, but payload-level HTTPS inspection is not implemented yet (no MITM/TLS termination in sidecar).

Current behavior:

1. Sidecar can allow/deny `CONNECT host:port` and audit that decision.
2. Allowed HTTPS tunnels are forwarded transparently end-to-end.
3. Policy evaluation over decrypted HTTPS paths/verbs requires a future MITM card.

## CONNECT implementation note

Why this exists:

1. Pingora defaults to rejecting CONNECT with `405 Method Not Allowed` unless CONNECT proxying is explicitly enabled.
2. In E2E runs, enabling that switch still yielded `502 Bad Gateway` for real HTTPS CONNECT targets in our flow.

What was changed:

1. Sidecar now handles CONNECT tunnel lifecycle explicitly in the HTTP interceptor runtime.
2. The handshake (`host:port`) is still enforced and audited before tunnel establishment.
3. Tunnel relay is transparent TCP forwarding (no TLS MITM).
