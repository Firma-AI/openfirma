# CLI Reference

## firma-sidecar

### Usage

```text
firma-sidecar [OPTIONS]
```

### Options

| Flag | Short | Env var | Default | Description |
|---|---|---|---|---|
| `--config-file` | `-c` | `FIRMA_SIDECAR_CONFIG_FILE` | `firma_sidecar.toml` | TOML configuration file |
| `--health-bind-addr` | | `FIRMA_SIDECAR_HEALTH_BIND_ADDR` | `127.0.0.1:9000` | Health check bind address |
| `--log-file` | `-L` | `FIRMA_SIDECAR_LOG_FILE` | none | File path for log output |
| `--log-filter` | `-f` | `FIRMA_SIDECAR_LOG_FILTER` | none | Tracing filter directive |
| `--log-level` | `-l` | `FIRMA_SIDECAR_LOG_LEVEL` | `info` | Log level |

CLI flag takes precedence over env var. Valid log levels: `trace`, `debug`, `info`, `warn`, `error`.

### Examples

```bash
# Start with defaults
firma-sidecar

# Config file + debug logging
firma-sidecar -c /etc/firma/sidecar.toml -l debug

# Log to file with filter
firma-sidecar -L /var/log/firma.log -f "firma_sidecar=debug,tower=warn"

# Using environment variables
export FIRMA_SIDECAR_CONFIG_FILE=/etc/firma/sidecar.toml
export FIRMA_SIDECAR_LOG_LEVEL=debug
firma-sidecar
```

### Health check

```bash
curl http://127.0.0.1:9000/healthz
# {"status":"ok"}
```

Default address: `127.0.0.1:9000`. Override with `--health-bind-addr`.

### Shutdown

SIGTERM / SIGINT triggers a graceful drain up to `interceptor.drain_timeout_secs`, then exits `0`.

| Code | When |
|---|---|
| `0` | Graceful shutdown after SIGINT / SIGTERM |
| `1` | Configuration error or startup failure |

### Startup log contract

On every successful start, exactly 7 INFO lines appear in order:

```text
config loaded             path="…"
mapping table loaded      rules=N
policy bundle loaded      version="…" policies=N
authority stream connected endpoint="…"
connector registry built  hosts=N default_timeout_ms=T
interceptor listening     addr="…"
ready
```

Wait for `ready` before sending traffic.

---

## firma-authority

### Usage

```text
firma-authority [OPTIONS] [COMMAND]
```

### Commands

| Command | Alias | Description |
|---|---|---|
| `serve` | (default) | Start the gRPC Authority server |
| `revocations add <token-id>` | `revoke`, `rev` | Add token to revocation store |
| `revocations compact` | | Remove expired entries from revocation file |
| `generate-key` | | Generate a new Ed25519 key pair |
| `issue` | | Pre-issue a capability seed TOML file |

### Options

| Flag | Short | Description |
|---|---|---|
| `--config` | `-c` | Path to TOML configuration file |

### `firma-authority issue` flags

| Flag | Required | Default | Description |
|---|---|---|---|
| `--agent-id` | yes | | Token agent identity |
| `--session-id` | yes | | Token session identity |
| `--action` | yes (repeat) | | Action class(es) the token covers |
| `--resource-scope` | no | `*` | Resource scope pattern |
| `--ttl-seconds` | no | `3600` | Requested TTL (clamped by `max_ttl_seconds`) |
| `--output` / `-o` | yes | | Path to write the seed TOML |

### Examples

```bash
# Start the authority
firma-authority --config examples/demo/authority.toml

# Generate a new signing key
firma-authority generate-key --output authority.key

# Pre-issue a capability seed
firma-authority --config authority.toml issue \
  --agent-id demo-agent \
  --session-id demo-session \
  --action communication.external.send \
  --resource-scope '*' \
  --ttl-seconds 3600 \
  --output capability-demo-agent.toml

# Revoke a token
firma-authority revocations add 3713c5fc-b569-650c-c780-c64051473370 --reason "incident"
```
