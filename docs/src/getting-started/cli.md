# CLI Usage

## Starting the sidecar

```bash
firma-sidecar
```

Default behaviour with no arguments:

- Interceptor binds on `0.0.0.0:8080` (HTTP proxy mode).
- Health check endpoint listens on `127.0.0.1:9000`.
- Logs to stdout at `info` level.
- Config read from `firma_sidecar.toml` in the current directory.

## Pointing at a config file

```bash
firma-sidecar -c /etc/firma/sidecar.toml
```

The long form is `--config-file`. An empty config file is valid; all settings
fall back to their defaults.

## Adjusting log level

```bash
firma-sidecar -l debug
```

The long form is `--log-level`. Valid values: `trace`, `debug`, `info`,
`warn`, `error`.

## Logging to file with a filter

```bash
firma-sidecar -L /var/log/firma.log -f "firma_sidecar=debug,tower=warn"
```

- `-L` / `--log-file` — write log output to a file instead of stdout.
- `-f` / `--log-filter` — a `tracing`-compatible directive string that
  overrides the simple level flag for fine-grained per-module filtering.

## Health check

```bash
curl http://127.0.0.1:9000/healthz
```

Returns `200 OK` with body:

```json
{"status":"ok"}
```

The health endpoint is available as soon as the sidecar reaches `ready`. Use
it in readiness probes to gate traffic.

## Graceful shutdown

Send `SIGTERM` or `SIGINT`. The Sidecar:

1. Stops accepting new connections immediately.
2. Drains in-flight requests up to `interceptor.drain_timeout_secs`
   (default 30 s).
3. Exits with code `0`.

## Startup readiness

On successful start the Sidecar emits exactly 7 INFO lines, ending with
`ready`:

```text
config loaded             path="…"
mapping table loaded      rules=N
policy bundle loaded      version="…" policies=N
authority stream connected endpoint="…"
connector registry built  hosts=N default_timeout_ms=T
interceptor listening     addr="…"
ready
```

Do not send traffic until the `ready` line appears. Readiness probes should
poll the health endpoint rather than parse log output.

## Full reference

See [CLI Reference](../reference/cli.md) for the complete flag listing with
types, defaults, and environment variable equivalents.
