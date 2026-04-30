# CLI Reference

## `firma-sidecar`

### Usage

```text
firma-sidecar [OPTIONS]
```

### Options

| Flag                 | Short | Env var                          | Default              | Description               |
| -------------------- | ----- | -------------------------------- | -------------------- | ------------------------- |
| `--config-file`      | `-c`  | `FIRMA_SIDECAR_CONFIG_FILE`      | `firma_sidecar.toml` | TOML configuration file   |
| `--health-bind-addr` |       | `FIRMA_SIDECAR_HEALTH_BIND_ADDR` | `127.0.0.1:9000`     | Health check bind address |
| `--log-file`         | `-L`  | `FIRMA_SIDECAR_LOG_FILE`         | none                 | File path for log output  |
| `--log-filter`       | `-f`  | `FIRMA_SIDECAR_LOG_FILTER`       | none                 | Tracing filter directive  |
| `--log-level`        | `-l`  | `FIRMA_SIDECAR_LOG_LEVEL`        | `info`               | Log level                 |

All options can be set through environment variables. CLI flags take precedence
over environment variables.

Valid log levels are `trace`, `debug`, `info`, `warn`, and `error`.

### Examples

Start with defaults:

```bash
firma-sidecar
```

Specify a config file and debug logging:

```bash
firma-sidecar -c /etc/firma/sidecar.toml -l debug
```

Log to a file with a filter:

```bash
firma-sidecar -L /var/log/firma.log -f "firma_sidecar=debug,tower=warn"
```

Use environment variables:

```bash
export FIRMA_SIDECAR_CONFIG_FILE=/etc/firma/sidecar.toml
export FIRMA_SIDECAR_LOG_LEVEL=debug
firma-sidecar
```

### Health Check

The sidecar exposes an HTTP health check server on the address specified by
`--health-bind-addr`. The default is `127.0.0.1:9000`.

### Shutdown

The sidecar handles `SIGTERM` and `SIGINT` for graceful shutdown:

1. Stop accepting new connections.
2. Drain in-flight requests up to `interceptor.drain_timeout_secs`.
3. Exit with code `0`.

### Standalone startup log contract

On every successful start the sidecar emits exactly seven INFO lines
in order. Operators automating the binary should wait for the final
`ready` line before sending traffic; the `examples/demo/` runbook
reproduces the contract and the `demo-e2e` CI gate scrapes it.

```text
config loaded             path="…"
mapping table loaded      rules=N
policy bundle loaded      version="…" policies=N
authority stream connected endpoint="…"
connector registry built  hosts=N default_timeout_ms=T
interceptor listening     addr="…"
ready
```

`policy bundle loaded version` is the eight-character hex prefix of
the SHA-256 of the concatenated `.cedar` files in `policy.dir`. Line 4
fires unconditionally; when `policy.authority_url` is unset the
endpoint is reported as `(disabled)`.

### Exit codes

| Code | When                                                              |
| ---- | ----------------------------------------------------------------- |
| `0`  | Graceful shutdown after `SIGINT` / `SIGTERM`.                     |
| `1`  | Configuration parse error, validation error, or startup failure. |


## `firma-authority`

Reference Authority binary used for local development. Issues
PASETO v4 capability tokens, streams policy bundles and
revocations. Pre-flight only, never on the hot path.

### `firma-authority issue`

Issues a signed capability token directly from the loaded Cedar
bundle and writes it to a TOML seed file consumable by the
sidecar `[capability_seed]` section. Stop-gap until the sidecar
wires the gRPC `IssueCapability` client; not intended for
production traffic.

```bash
firma-authority --config authority.toml issue \
  --agent-id demo-agent \
  --session-id demo-session \
  --action communication.external.send \
  --resource-scope '*' \
  --ttl-seconds 3600 \
  --output capability-demo-agent.toml
```

| Flag               | Required | Default | Description                                              |
| ------------------ | -------- | ------- | -------------------------------------------------------- |
| `--agent-id`       | yes      |         | Token agent identity.                                    |
| `--session-id`     | yes      |         | Token session identity.                                  |
| `--action`         | yes      |         | Action class. Repeat the flag for multiple.              |
| `--resource-scope` | no       | `*`     | Resource scope pattern.                                  |
| `--ttl-seconds`    | no       | `3600`  | Requested TTL. Clamped by `max_ttl_seconds` in config.   |
| `--output`/`-o`    | yes      |         | Path to write the seed TOML.                             |

The subcommand evaluates the loaded Cedar bundle exactly like
the gRPC `IssueCapability` handler — a Cedar deny exits non-zero
with `issuance failed: cedar denied issuance (...): ...`.

The output TOML carries the raw `v4.public....` token plus the
matching claims; the sidecar consumes it via
`[capability_seed].paths` and verifies the signature with
`[authority].public_key_path`.
