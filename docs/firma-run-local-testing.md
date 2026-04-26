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

## Run sidecar + codex

Terminal A:

```bash
cargo run -p firma-sidecar -- -c .local/firma_sidecar.local.toml
```

Terminal B:

```bash
cargo run -p firma-run -- run --profile codex -- codex
```

## Run the local E2E harness

```bash
scripts/e2e-firma-run.sh
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

`firma-sidecar` HTTP interceptor currently lacks full HTTPS CONNECT tunneling/MITM support, so real HTTPS API flows (for example OpenAI over HTTPS proxy) are not fully functional yet.

Tracking recommendation:

1. Card for HTTPS CONNECT support.
2. Separate card for HTTPS MITM/L7 inspection.
