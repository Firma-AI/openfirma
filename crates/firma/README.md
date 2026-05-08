# `firma` — Unified Firma OSS CLI

Single binary exposing every Firma OSS production component as a subcommand.

## Trust chain

1. **`firma authority`** — pre-flight only. Issues PASETO v4 capability
   tokens, streams policy bundles and revocations.
2. **`firma sidecar`** — hot-path enforcement. Every outbound agent call
   passes through it; fail-closed.
3. **`firma run`** — wrapper that confines an agent process inside a
   sandbox backend and forces all egress through the sidecar.

## Install

From source:

```bash
cargo install --path crates/firma
```

The resulting binary is named `firma`.

## Global flags

| Flag           | Env                | Default  | Description                                 |
| -------------- | ------------------ | -------- | ------------------------------------------- |
| `--log-filter` | `FIRMA_LOG_FILTER` | `info`   | `EnvFilter` directive (e.g. `firma=debug`). |
| `--log-file`   | `FIRMA_LOG_FILE`   | _stderr_ | Write logs to file (truncated on open).     |
| `--help`       | —                  | —        | Print help.                                 |
| `--version`    | —                  | —        | Print version.                              |

## Subcommands

### `firma sidecar`

Run the enforcement proxy.

```bash
firma sidecar --config-file /etc/firma/sidecar.toml
```

| Flag                 | Env                              | Default              |
| -------------------- | -------------------------------- | -------------------- |
| `-c, --config-file`  | `FIRMA_SIDECAR_CONFIG_FILE`      | `firma_sidecar.toml` |
| `--health-bind-addr` | `FIRMA_SIDECAR_HEALTH_BIND_ADDR` | `127.0.0.1:9000`     |

Config schema: see `crates/firma-sidecar/src/config.rs`.

### `firma authority`

Run the mini-Authority dev server (no subcommand) or manage on-disk
state.

```bash
# Serve gRPC
firma authority --config /etc/firma/authority.toml

# Generate signing key
firma authority generate-key -o auth.key

# Issue a capability seed
firma authority issue \
  --agent-id agent-1 \
  --session-id 00000000-0000-0000-0000-000000000000 \
  --action fep.read --action fep.write \
  --resource-scope 'wttr.in*' \
  --ttl-seconds 3600 \
  --output seed.toml

# Revocations
firma authority revocations add <token-id> --reason 'compromised'
firma authority revocations compact
```

### `firma run`

Wrap an agent command behind a sandbox backend.

```bash
firma run --profile generic -- python agent.py
```

| Flag                       | Description                                     |
| -------------------------- | ----------------------------------------------- |
| `--profile <id>`           | Built-in profile id (default: `generic`).       |
| `--config <path>`          | Optional runtime config (.toml/.yaml).          |
| `--backend <kind>`         | Override: `bwrap`, `vz`, `wsl2`, `firecracker`. |
| `--sidecar-endpoint <url>` | Override sidecar endpoint.                      |
| `--capability-file <path>` | Capability lease refresh source.                |
| `--identity-mode <mode>`   | `sandbox-user` or `host-user`.                  |
| `--preserve-host-user`     | Force host UID/GID inside sandbox.              |
| `--print-effective-config` | Dump resolved config as JSON before exec.       |

Wrapped command and args after `--`.

### Hidden helpers

`firma __dns-stub` and `firma __proxy-bridge` are spawned by
`firma run` inside the sandbox. They are not for direct operator use.
