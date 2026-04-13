# CLI Reference

## Usage

```text
firma-sidecar [OPTIONS]
```

## Options

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

## Examples

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

## Health Check

The sidecar exposes an HTTP health check server on the address specified by
`--health-bind-addr`. The default is `127.0.0.1:9000`.

## Shutdown

The sidecar handles `SIGTERM` and `SIGINT` for graceful shutdown:

1. Stop accepting new connections.
2. Drain in-flight requests up to `interceptor.drain_timeout_secs`.
3. Exit with code `0`.
