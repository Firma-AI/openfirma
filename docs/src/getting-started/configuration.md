# Configuration

## Minimal config

An empty `firma_sidecar.toml` is valid. The Sidecar starts with all defaults:

| Setting          | Default                   |
| ---------------- | ------------------------- |
| Interceptor      | HTTP proxy `0.0.0.0:8080` |
| Policy directory | `./policies/`             |
| CA directory     | `./firma-ca/`             |
| Log level        | `info`                    |
| Mapping rules    | `mapping-rules.toml`      |

## Common knobs

### `[interceptor]`

```toml
[interceptor]
mode               = "http_proxy"   # http_proxy | grpc | unix_socket
listen_addr        = "127.0.0.1:9090"
drain_timeout_secs = 30             # graceful shutdown drain window
```

### `[interceptor.https_mitm]`

```toml
[interceptor.https_mitm]
enabled         = true
intercept_hosts = ["api.openai.com", "*.resend.com"]
bypass_hosts    = ["status.openai.com"]
strict_hosts    = ["api.openai.com"]   # fail closed if MITM can't apply
```

### `[policy]`

```toml
[policy]
dir           = "./policies"
authority_url = "http://127.0.0.1:50051"  # omit for dev-mode (no Authority)
```

### `[ca]`

```toml
[ca]
dir = "./firma-ca"   # CA material is auto-generated on first run
```

### `[log]`

```toml
[log]
level = "info"   # trace | debug | info | warn | error
```

### `[audit]`

```toml
[audit]
sink             = "stdout"
signing_key_path = "./audit.key"
```

## Mapping rules

```toml
[mapping]
rules_path        = "mapping-rules.toml"
default_protected = true   # unlisted hosts are denied (fail-closed)
```

A minimal `mapping-rules.toml`:

```toml
[[rules]]
method       = "POST"
host         = "api.openai.com"
path         = "/v1/chat/completions"
action_class = "llm.inference"
```

Each rule maps an HTTP `(method, host, path)` triple to a canonical
`action_class` from the registry. The Sidecar also ships ready-made mapping
files for common providers:

- `crates/firma-sidecar/config/mappings/github.toml` — 44 GitHub REST
  endpoints across 12 action classes.
- `crates/firma-sidecar/config/mappings/stripe.toml` — 88 Stripe REST
  endpoints across 14 action classes.
- `crates/firma-sidecar/config/mappings/gmail.toml` — 41 Gmail REST
  endpoints across 7 action classes.

To load additional mapping files on top of the primary one, use
`rules_paths`:

```toml
[enforcement.mapping]
rules_path  = "config/mappings/default.toml"
rules_paths = [
  "crates/firma-sidecar/config/mappings/github.toml",
  "crates/firma-sidecar/config/mappings/stripe.toml",
  "crates/firma-sidecar/config/mappings/gmail.toml",
]
```

Duplicate `(method, host, path)` tuples across merged files are rejected at
startup (fail-closed).

## Validation

Config errors are reported at startup before any traffic is accepted. A
validation error exits with code `1` and a message of the form:

```text
ERROR configuration error: ...
```

The Sidecar validates TOML syntax, required fields, valid enum values,
wildcard patterns, and CA file coherence. No requests are accepted if
validation fails.

## Full reference

See [Configuration Reference](../reference/configuration.md) for the complete
field listing with types, defaults, and constraints.
