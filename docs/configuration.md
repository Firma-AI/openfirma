# Configuration Reference

`firma-sidecar` reads configuration from a TOML file specified with the
`--config-file` CLI flag. The default path is `firma_sidecar.toml`.

Configuration is validated at startup. Invalid fields cause the sidecar to exit
before accepting requests.

## Minimal Configuration

An empty file is valid. Defaults are applied for every section:

```toml
# Empty config uses all defaults.
# Interceptor: HTTP proxy on 0.0.0.0:8080
# Policy dir: ./policies/
# CA dir: ./firma-ca/
# Log level: info
# Mapping rules: mapping-rules.toml
```

## Full Example

```toml
[interceptor]
mode = "http_proxy"
listen_addr = "127.0.0.1:9090"
drain_timeout_secs = 15
# socket_path = "/tmp/firma.sock"

[policy]
dir = "/etc/firma/policies"
authority_url = "https://authority.example.com"

[ca]
dir = "/etc/firma/ca"

[log]
level = "debug"

[credentials.openai]
target_host = "api.openai.com"
header = "Authorization"
value_from_env = "OPENAI_API_KEY"
prefix = "Bearer "

[mapping]
rules_path = "/etc/firma/rules.toml"
default_protected = false

[capability_validation]
clock_skew_tolerance_seconds = 5

[constraint_enforcement]
bundle_ttl_seconds = 60

[audit]
sink = "wal"
file_path = "/var/log/firma/audit.jsonl"
grpc_url = "https://audit.example.com"
wal_path = "/var/lib/firma/wal"
wal_max_bytes = 104857600
signing_key_path = "/etc/firma/audit.pem"
# signing_key_env = "FIRMA_AUDIT_SIGNING_KEY"
```

## Sections

### `[interceptor]`

Selects the interception mode and transport-specific parameters.

| Field                | Type        | Default        | Description                         |
| -------------------- | ----------- | -------------- | ----------------------------------- |
| `mode`               | string      | `http_proxy`   | `http_proxy`, `grpc`, `unix_socket` |
| `listen_addr`        | socket addr | `0.0.0.0:8080` | TCP address for HTTP proxy and gRPC |
| `socket_path`        | path        | none           | Required when mode is `unix_socket` |
| `drain_timeout_secs` | u64         | `30`           | Shutdown drain timeout in seconds   |

Validation:

- `drain_timeout_secs` must be greater than `0`.
- On Unix, `socket_path` must be set and non-empty when mode is `unix_socket`.

### `[policy]`

Policy source settings.

| Field           | Type   | Default       | Description                         |
| --------------- | ------ | ------------- | ----------------------------------- |
| `dir`           | path   | `./policies/` | Directory containing `.cedar` files |
| `authority_url` | string | none          | Optional Authority gRPC URL         |

Validation:

- `dir` must not be empty.
- `authority_url`, when set, must not be empty or whitespace-only.

### `[ca]`

Certificate authority directory.

| Field | Type | Default       | Description                       |
| ----- | ---- | ------------- | --------------------------------- |
| `dir` | path | `./firma-ca/` | Directory containing CA material  |

Validation:

- `dir` must not be empty.

### `[log]`

Log settings from the configuration file. CLI logging flags override these
settings.

| Field   | Type   | Default | Description                                |
| ------- | ------ | ------- | ------------------------------------------ |
| `level` | string | `info`  | `trace`, `debug`, `info`, `warn`, `error`  |

Validation:

- `level` must be one of `trace`, `debug`, `info`, `warn`, or `error`.

### `[credentials.<label>]`

Per-target credential injection. Matching outbound requests have the specified
header injected with a value read from an environment variable.

| Field            | Type   | Required | Description                           |
| ---------------- | ------ | -------- | ------------------------------------- |
| `target_host`    | string | yes      | Host this credential applies to       |
| `header`         | string | yes      | HTTP header name to inject            |
| `value_from_env` | string | yes      | Environment variable to read          |
| `prefix`         | string | no       | Prefix prepended to the env var value |

Validation:

- `target_host`, `header`, and `value_from_env` must not be empty.

### `[mapping]`

Intent normalization and mapping rules configuration.

| Field               | Type   | Default              | Description                               |
| ------------------- | ------ | -------------------- | ----------------------------------------- |
| `rules_path`        | string | `mapping-rules.toml` | Path to the mapping rules TOML file       |
| `default_protected` | bool   | `true`               | Whether unlisted hosts are protected      |

Validation:

- `rules_path` must not be empty.

### `[capability_validation]`

Stage 1 settings.

| Field                          | Type | Default | Description                    |
| ------------------------------ | ---- | ------- | ------------------------------ |
| `clock_skew_tolerance_seconds` | u64  | `0`     | Token expiry clock skew window |

### `[constraint_enforcement]`

Stage 2 settings.

| Field                | Type | Default | Description                           |
| -------------------- | ---- | ------- | ------------------------------------- |
| `bundle_ttl_seconds` | u64  | `30`    | Policy bundle maximum age before deny |

### `[audit]`

Audit event emitter settings. Controls where enforcement events are written and
how they are signed.

| Field              | Type   | Default     | Description                                     |
| ------------------ | ------ | ----------- | ----------------------------------------------- |
| `sink`             | string | `stdout`    | `stdout`, `file`, `grpc`, `wal`                 |
| `file_path`        | path   | none        | Append-only file path (required for `file` sink) |
| `grpc_url`         | string | none        | Audit service URL (required for `grpc`/`wal`)   |
| `wal_path`         | path   | none        | Local WAL directory (required for `wal` sink)   |
| `wal_max_bytes`    | u64    | `104857600` | Maximum WAL size in bytes (100 MiB)             |
| `signing_key_path` | path   | none        | ECDSA private key file path                     |
| `signing_key_env`  | string | none        | Env var containing ECDSA private key (PEM)      |

Validation:

- `file_path` must be set and non-empty when sink is `file`.
- `grpc_url` must be set and non-empty when sink is `grpc` or `wal`.
- `wal_path` must be set and non-empty when sink is `wal`.
- `wal_max_bytes` must be greater than `0`.
- `signing_key_path` and `signing_key_env` are mutually exclusive.

## Mapping Rules File

The mapping rules file referenced by `mapping.rules_path` defines how raw HTTP
requests are classified into canonical action classes.

```toml
[[rules]]
method = "POST"
host = "api.openai.com"
path = "/v1/chat/completions"
action_class = "llm.inference"

[[rules]]
host = "*.example.com"
action_class = "http.get"
```

| Field          | Type   | Required | Description                              |
| -------------- | ------ | -------- | ---------------------------------------- |
| `method`       | string | no       | HTTP method to match; omit for any       |
| `host`         | string | yes      | Host pattern; `*` wildcard supported     |
| `path`         | string | no       | Path pattern; `*` wildcard supported     |
| `action_class` | string | yes      | Canonical action class from the registry |

Validation:

- At least one rule must be present.
- `host` and `action_class` must not be empty.
- `method`, when set, must be a valid HTTP method: `GET`, `POST`, `PUT`,
  `DELETE`, `PATCH`, `HEAD`, or `OPTIONS`.
