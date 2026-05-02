# Configuration Reference

`firma-sidecar` reads configuration from a TOML file specified with the
`--config-file` CLI flag. The default path is `firma_sidecar.toml`.

Configuration is validated at startup. Invalid fields cause the sidecar to exit
before accepting requests.

> **See also**: `examples/demo/sidecar.toml` is the canonical
> end-to-end reference. `make demo-ci` boots the sidecar against it
> and gates merges via the `demo-e2e` GitHub Actions workflow.

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
max_request_body_bytes = 4194304
# socket_path = "/tmp/firma.sock"

[interceptor.connect_relay]
setup_timeout_secs = 10
session_max_secs = 600

[interceptor.https_mitm]
enabled = true
intercept_hosts = ["api.openai.com", "api.supabase.com", "*.resend.com"]
bypass_hosts = ["status.openai.com"]
strict_hosts = ["api.openai.com"]
cert_ttl_secs = 86400
cert_cache_capacity = 1024

[policy]
dir = "/etc/firma/policies"
authority_url = "https://authority.example.com"

[ca]
dir = "/etc/firma/ca"

[log]
level = "debug"

[credentials.openai]
mode = "basic"
target_host = "api.openai.com"
header = "Authorization"
value_from_env = "OPENAI_API_KEY"
prefix = "Bearer "

[credentials.stripe]
mode = "vault"
target_host = "api.stripe.com"
header = "Authorization"
secret_path = "/run/secrets/stripe_token"
prefix = "Bearer "

[mapping]
rules_path = "/etc/firma/rules.toml"
default_protected = false

[capability_validation]
clock_skew_tolerance_seconds = 5

[constraint_enforcement]
bundle_ttl_seconds = 60

[connector]
default_timeout_ms = 15000

[[connector.hosts]]
host = "api.openai.com"
rps = 60
burst = 10
timeout_ms = 60000

[authority]
connect_timeout_secs = 10
reconnect_min_backoff_ms = 250
reconnect_max_backoff_secs = 30
revocation_readiness_grace_ms = 500
revocation_fail_closed_on_disconnect = false

[revocation]
capacity = 1000000
fpr = 0.0001
lru_capacity = 100000

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
| `max_request_body_bytes` | usize   | `4194304`      | Max inbound request body size (bytes) |

Validation:

- `drain_timeout_secs` must be greater than `0`.
- `max_request_body_bytes` must be greater than `0`.
- On Unix, `socket_path` must be set and non-empty when mode is `unix_socket`.

### `[interceptor.connect_relay]`

Timeout controls for CONNECT tunnel and HTTPS MITM relay sessions.

| Field                | Type | Default | Description                                              |
| -------------------- | ---- | ------- | -------------------------------------------------------- |
| `setup_timeout_secs` | u64  | `10`    | Timeout for CONNECT upgrade and upstream setup/handshake |
| `session_max_secs`   | u64  | `600`   | Hard cap for an individual CONNECT/MITM session lifetime |

Validation:

- `setup_timeout_secs` must be greater than `0`.
- `session_max_secs` must be greater than `0`.

### `[interceptor.https_mitm]`

Optional TLS MITM controls for HTTPS `CONNECT` traffic in `http_proxy` mode.
Defaults are MITM-enabled with a curated common API host list. Hosts not matched
by `intercept_hosts` stay in transparent CONNECT tunnel mode (destination-level
enforcement only).

| Field                 | Type        | Default  | Description                                        |
| --------------------- | ----------- | -------- | -------------------------------------------------- |
| `enabled`             | bool        | `true`   | Enables MITM for hosts matched by `intercept_hosts` |
| `ca_cert_path`        | path        | none     | Optional explicit CA certificate path              |
| `ca_key_path`         | path        | none     | Optional explicit CA private key path              |
| `intercept_hosts`     | list<string>| curated common API hosts | Host patterns to intercept (`*` or `*.example.com`) |
| `bypass_hosts`        | list<string>| `[]`     | Host patterns to force CONNECT tunnel mode         |
| `strict_hosts`        | list<string>| `[]`     | Host patterns that must be intercepted             |
| `cert_ttl_secs`       | u64         | `86400`  | Leaf certificate cache TTL in seconds              |
| `cert_cache_capacity` | usize       | `1024`   | Maximum number of cached leaf certificates         |

Validation:

- Host lists (`intercept_hosts`, `bypass_hosts`, `strict_hosts`) cannot contain
  empty patterns.
- Wildcard patterns are DNS-label-aware and only support:
  - `*` (match any host)
  - `*.example.com` (match subdomains only, not apex `example.com`)
- Wildcards inside labels (for example `api.*.com`) are rejected.
- Wildcard suffixes must contain at least two DNS labels (for example
  `*.com` is rejected).
- If `enabled = true`, `intercept_hosts` must be non-empty.
- If `enabled = true`, `cert_ttl_secs` and `cert_cache_capacity` must be
  greater than `0`.
- If `ca_cert_path` / `ca_key_path` are omitted, first-run CA files are created
  under [`[ca].dir`](#ca) as `firma-ca.crt` and `firma-ca.key`.
- CA generation is first-run only. If either CA file already exists, the
  sidecar must load the existing cert/key pair exactly as-is or fail startup;
  it never regenerates, repairs, or replaces CA material from partial,
  malformed, unreadable, or mismatched state.
- On Unix, the CA private key is enforced as owner-only (`0600`); overly-open
  key permissions are rejected at startup.
- Intercepted DNS hostnames are validated with strict DNS label rules before
  leaf cert issuance.
- For hosts in `strict_hosts`, MITM preflight failures are returned as
  deterministic `403` fail-closed denies.
- For non-strict intercepted hosts, MITM preflight failures fall back to
  CONNECT tunnel mode.
- For intercepted hosts, HTTPS upgrade handshakes (for example WebSocket
  `Connection: Upgrade` + `Upgrade: websocket`) are policy-evaluated at
  handshake request time and then relayed as upgraded streams when allowed.

Default `intercept_hosts` includes common providers/services such as OpenAI,
Anthropic/Claude (`api.anthropic.com`, `platform.claude.com`, `claude.ai`,
`console.anthropic.com`), OpenRouter, Groq, Mistral, Cohere, Google
GenAI/Vertex, DeepSeek, Together, Fireworks, Replicate, Perplexity, xAI,
Supabase, Resend, Twilio, SendGrid, Stripe, Slack, and GitHub APIs.

#### Practical operating modes

The sidecar supports progressive rollout patterns. A useful mental model:

- `intercept_hosts` controls where you get L7 visibility/enforcement via MITM.
- `mapping.default_protected` controls whether unmapped traffic is blocked by
  policy (`true`) or allowed by default (`false`).

1. Open connectivity + targeted governance (recommended for onboarding)

Use when you want agents to keep working broadly, but still inspect/enforce
high-value destinations (for example model APIs, secrets-bearing backends, or
billing endpoints).

```toml
[interceptor.https_mitm]
enabled = true
intercept_hosts = ["api.anthropic.com", "platform.claude.com", "api.openai.com"]
strict_hosts = ["api.anthropic.com", "api.openai.com"]

[mapping]
default_protected = false
```

Behavior:

- Unmapped hosts are allowed (lower friction rollout).
- Intercepted hosts still flow through full intent normalization + policy +
  audit.
- `strict_hosts` fail closed if MITM setup cannot be established.

2. High-control / deny-by-default

Use when compliance posture requires explicit allowlists for all relevant
traffic.

```toml
[interceptor.https_mitm]
enabled = true
intercept_hosts = ["api.anthropic.com", "platform.claude.com", "api.openai.com"]
strict_hosts = ["api.anthropic.com", "platform.claude.com", "api.openai.com"]

[mapping]
default_protected = true
```

Behavior:

- Unmapped traffic is protected/denied unless explicit mapping/policy allows it.
- Intercepted strict hosts are fail-closed on MITM failures.

3. Destination-level governance only (no HTTPS decryption)

Use when you need host-level control but cannot run MITM for policy, legal, or
certificate-distribution reasons.

```toml
[interceptor.https_mitm]
enabled = false

[mapping]
default_protected = false
```

Behavior:

- Sidecar enforces at CONNECT destination level for HTTPS.
- No decrypted request path/body visibility for HTTPS.

### `[policy]`

Policy source settings.

| Field           | Type   | Default       | Description                         |
| --------------- | ------ | ------------- | ----------------------------------- |
| `dir`           | path   | `./policies/` | Directory containing `.cedar` files |
| `authority_url` | string | none          | Optional Authority gRPC URL         |

Validation:

- `dir` must not be empty.
- `authority_url`, when set, must not be empty or whitespace-only.

When `authority_url` is set, the sidecar spawns the Authority stream
clients (`WatchPolicyBundle`, `WatchRevocations`) described in
[`[authority]`](#authority). When unset, the sidecar runs in dev
mode: no stream clients, and the readiness gate is pre-populated so
traffic is not blocked.

### `[ca]`

Certificate authority directory.

| Field | Type | Default       | Description                      |
| ----- | ---- | ------------- | -------------------------------- |
| `dir` | path | `./firma-ca/` | Directory containing CA material |

Validation:

- `dir` must not be empty.

### `[log]`

Log settings from the configuration file. CLI logging flags override these
settings.

| Field   | Type   | Default | Description                               |
| ------- | ------ | ------- | ----------------------------------------- |
| `level` | string | `info`  | `trace`, `debug`, `info`, `warn`, `error` |

Validation:

- `level` must be one of `trace`, `debug`, `info`, `warn`, or `error`.

### `[credentials.<label>]`

Per-target credential injection. Each entry selects a mode (`basic` or `vault`)
and provides the fields that mode requires. Matching outbound requests have the
specified header injected with the resolved credential value.

Multiple entries may target the same `target_host`. Headers from all matching
entries are merged. If no credentials are configured for a target host, the
request proceeds with no injected headers.

When credentials _are_ configured for a host but cannot be resolved (e.g. a
Vault-rendered secret file is missing), the request is denied with
`CREDENTIAL_INJECTION_FAILED` (fail-closed).

| Field            | Type   | Default | Description                                    |
| ---------------- | ------ | ------- | ---------------------------------------------- |
| `mode`           | string | `basic` | `basic` (env var at startup) or `vault` (file) |
| `target_host`    | string |         | Host this credential applies to                |
| `header`         | string |         | HTTP header name to inject                     |
| `prefix`         | string | none    | Prefix prepended to the resolved value         |
| `value_from_env` | string | none    | Environment variable to read (basic mode)      |
| `secret_path`    | path   | none    | Vault Agent secret file path (vault mode)      |

#### Basic mode

Reads a static credential from an environment variable once at startup. The
sidecar exits if the variable is missing or empty.

```toml
[credentials.openai]
mode = "basic"
target_host = "api.openai.com"
header = "Authorization"
value_from_env = "OPENAI_API_KEY"
prefix = "Bearer "
```

#### Vault mode

Reads a secret from a file on disk rendered by Vault Agent. The file is read
on each request, so rotated secrets take effect immediately.

```toml
[credentials.stripe]
mode = "vault"
target_host = "api.stripe.com"
header = "Authorization"
secret_path = "/run/secrets/stripe_token"
prefix = "Bearer "
```

Validation:

- `target_host` and `header` must not be empty.
- Basic mode: `value_from_env` must be set and non-empty; the referenced
  environment variable must be set and non-empty at startup.
- Vault mode: `secret_path` must be set and non-empty.

### `[mapping]`

Intent normalization and mapping rules configuration.

| Field               | Type   | Default              | Description                          |
| ------------------- | ------ | -------------------- | ------------------------------------ |
| `rules_path`        | string | `mapping-rules.toml` | Path to the mapping rules TOML file  |
| `default_protected` | bool   | `true`               | Whether unlisted hosts are protected |

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

The authoritative TTL at runtime comes from the `ttl_seconds` field on
the `PolicyBundle` pushed by the Authority over `WatchPolicyBundle`.
`bundle_ttl_seconds` here is the dev-mode fallback used only until the
first push arrives.

### `[connector]`

Outbound dispatch defaults and per-host overrides.

| Field                | Type | Default | Description                               |
| -------------------- | ---- | ------- | ----------------------------------------- |
| `default_timeout_ms` | u64  | `30000` | Fallback dispatch timeout in milliseconds |
| `hosts`              | list | empty   | Per-host overrides, see table below       |

Each `[[connector.hosts]]` entry is required to state every field
explicitly — inheriting silent global defaults is not allowed.

| Field        | Type   | Required | Description                                |
| ------------ | ------ | -------- | ------------------------------------------ |
| `host`       | string | yes      | Target host (exact match)                  |
| `rps`        | u32    | yes      | Sustained token-bucket refill rate (req/s) |
| `burst`      | u32    | yes      | Token-bucket burst capacity                |
| `timeout_ms` | u64    | yes      | Dispatch timeout in milliseconds           |

Validation:

- `default_timeout_ms` must be greater than `0`.
- Each host entry must set a non-empty `host`, and each of `rps`,
  `burst`, and `timeout_ms` must be greater than `0`.
- Duplicate `host` entries are rejected.

### `[authority]`

Tuning for the background Authority stream clients
(`WatchPolicyBundle`, `WatchRevocations`). Only consulted when
`policy.authority_url` is set; when unset the sidecar runs in dev
mode and this section is ignored.

| Field                                  | Type | Default | Description                                                   |
| -------------------------------------- | ---- | ------- | ------------------------------------------------------------- |
| `connect_timeout_secs`                 | u64  | `10`    | Connection timeout for the tonic channel                      |
| `reconnect_min_backoff_ms`             | u64  | `250`   | Minimum reconnect backoff                                     |
| `reconnect_max_backoff_secs`           | u64  | `30`    | Maximum reconnect backoff                                     |
| `revocation_readiness_grace_ms`        | u64  | `500`   | Grace period after revocation stream opens before readiness   |
| `revocation_fail_closed_on_disconnect` | bool | `false` | Flip revocation readiness back to false when the stream drops |
| `public_key_path`                      | path | none    | Authority Ed25519 public key. Required when `[capability_seed].paths` is non-empty so the sidecar can verify seeded tokens. |

Validation:

- `connect_timeout_secs`, `reconnect_min_backoff_ms`, and
  `reconnect_max_backoff_secs` must all be greater than `0`.
- `reconnect_max_backoff_secs * 1000` must be ≥
  `reconnect_min_backoff_ms`.

Behavior notes:

- Requests are denied with `POLICY_BUNDLE_NOT_READY` until the first
  bundle has been applied and `REVOCATION_CACHE_NOT_READY` until the
  revocation stream has either received its first event or the grace
  period has elapsed — whichever happens first.
- The policy bundle TTL (carried in each `PolicyBundleUpdate`) is
  authoritative for fail-closed on disconnect. When the deadline
  elapses without a refresh, Stage 2 denies with `PolicyBundleStale`.
- `revocation_fail_closed_on_disconnect = true` is the opt-in strict
  mode: a revocation stream drop flips readiness off and the sidecar
  denies all traffic with `REVOCATION_CACHE_NOT_READY` until the
  stream recovers.

### `[revocation]`

Two-layer revocation cache sizing. Bloom filter for O(1) negative
checks; LRU for confirmed positives.

| Field          | Type  | Default   | Description                                         |
| -------------- | ----- | --------- | --------------------------------------------------- |
| `capacity`     | usize | `1000000` | Expected distinct revoked tokens the bloom is sized |
| `fpr`          | f64   | `0.0001`  | Target bloom false positive rate                    |
| `lru_capacity` | usize | `100000`  | LRU capacity for confirmed-positive revocations     |

Validation:

- `capacity` and `lru_capacity` must be greater than `0`.
- `fpr` must be in the open interval `(0.0, 1.0)`.

Defaults give roughly 14 MB total footprint (bloom 2.4 MB + LRU
12 MB), well inside the `< 100 MB` RSS budget.

### `[audit]`

Audit event emitter settings. Controls where enforcement events are written and
how they are signed.

| Field              | Type   | Default     | Description                                      |
| ------------------ | ------ | ----------- | ------------------------------------------------ |
| `sink`             | string | `stdout`    | `stdout`, `file`, `grpc`, `wal`                  |
| `file_path`        | path   | none        | Append-only file path (required for `file` sink) |
| `grpc_url`         | string | none        | Audit service URL (required for `grpc`/`wal`)    |
| `wal_path`         | path   | none        | Local WAL directory (required for `wal` sink)    |
| `wal_max_bytes`    | u64    | `104857600` | Maximum WAL size in bytes (100 MiB)              |
| `signing_key_path` | path   | none        | ECDSA private key file path                      |
| `signing_key_env`  | string | none        | Env var containing ECDSA private key (PEM)       |

Validation:

- `file_path` must be set and non-empty when sink is `file`.
- `grpc_url` must be set and non-empty when sink is `grpc` or `wal`.
- `wal_path` must be set and non-empty when sink is `wal`.
- `wal_max_bytes` must be greater than `0`.
- `signing_key_path` and `signing_key_env` are mutually exclusive.

### `[capability_seed]`

Static capability provisioning. Each path entry is a TOML file
produced by `firma-authority issue` (see `docs/cli.md`). The sidecar
loads every seed at startup, parses it, and pre-populates the
`CapabilityMap` so Stage 1 has tokens to select against.

```toml
[capability_seed]
paths = ["./capability-demo-agent.toml"]
```

| Field   | Type       | Default | Description                                     |
| ------- | ---------- | ------- | ----------------------------------------------- |
| `paths` | `[string]` | `[]`    | Seed TOML files. Empty disables static seeding. |

Validation:

- Each entry in `paths` must be non-empty.

Behavior notes:

- Empty list means Stage 1 will deny every protected request that
  needs a token, since the `CapabilityMap` will be empty.
- `[authority].public_key_path` must be set when `paths` is
  non-empty; otherwise the verifier rejects every seeded token with
  `signature invalid: no authority public key configured`.
- This section is a stop-gap until the sidecar wires the gRPC
  `IssueCapability` client. Production deployments should not rely
  on it.

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
