# Configuration Reference

Every subcommand reads one shared, sectioned `firma.toml`. There is exactly
**one** schema. A single file holds top-level `[authority]`, `[sidecar.*]`
(`[sidecar.interceptor]` / `[sidecar.policy]` / `[sidecar.ca]` /
`[sidecar.audit]` / `[sidecar.mapping]`, plus any bare `[sidecar]` scalars),
and `[run]`. Each subcommand reads only its own section; section extraction
is fail-closed (a missing required section is a hard error).

When `--config` is **omitted**, that `firma.toml` is discovered from
`$FIRMA_CONFIG` or by walking up from `cwd` to `.firma/firma.toml` (see
[Config Discovery](cli.md#config-discovery)). An explicit `--config <path>`
only overrides the file location — the file still uses the same sectioned
shape and must be readable and valid TOML.

Configuration is validated at startup. Invalid fields cause the affected
binary to exit before accepting requests.

Unknown keys are rejected recursively rather than ignored. The only top-level
keys are `authority`, `sidecar`, and `run`; nested objects and tagged variants
are strict as well. Dynamic labels such as credential names, executable-policy
names, and Run profile names remain open, but every value under those labels
must match its schema. Firma validates all Run defaults and profiles while
parsing the file, including profiles that are not selected, so a typo or an
unsupported `backend` anywhere fails startup. Remove stale tables such as
`[project]` and `[sidecar.preflight]` instead of relying on them being ignored.

The following settings were removed because they never controlled runtime
behavior: `[authority].log_level`, `[sidecar.log]`,
`[sidecar.constraint_enforcement].bundle_ttl_seconds`,
`[sidecar.constraint_enforcement].enforcement_timeout_ms`, and Run profile
`allowed_domains`. Remove them from existing files. Configure process logging
with `--log-filter` / `FIRMA_LOG_FILTER`. Policy-bundle freshness is controlled
by the TTL advertised by the Authority, and seccomp artifact checksums are
always verified; `seccomp_policy.verify_checksum` is therefore no longer a
configurable choice.

## Scaffolded Example

`firma config` writes one sectioned `firma.toml` with all paths
absolutised under the resolved config and state directories. The shape is:

```toml
[authority]
listen_addr = "127.0.0.1:50051"
policy_dir = '/home/me/.config/firma/policies'
issuance_policy_dir = '/home/me/.config/firma/issuance-policies'
revocation_file = '/run/user/1000/firma/revocations.txt'
key_file = '/home/me/.config/firma/authority.key'
max_ttl = "1h"
bundle_ttl = "30s"

[sidecar.interceptor]
mode = "http_proxy"
listen_addr = "127.0.0.1:8080"

[sidecar.authority]
agent_id = "agt_01j0000000e008000000000001"
url = "http://127.0.0.1:50051"
public_key_path = '/home/me/.config/firma/authority.pub'

[sidecar.ca]
dir = '/run/user/1000/firma/generated-firma-ca'

[sidecar.audit]
signing_key_path = '/home/me/.config/firma/audit.key'

[sidecar.mapping]
rules_path = '/home/me/.config/firma/mapping-rules.toml'
```

The `[sidecar.*]` tables map onto the per-section reference below
(`[sidecar.interceptor]` documents the same fields as
[`[interceptor]`](#interceptor), `[sidecar.policy]` as
[`[policy]`](#policy), and so on). `[authority]` is the
`firma-authority` config; see
[the Authority README](../crates/firma-authority/README.md) for its fields.

## Registered identity and execution profile

`firma run` treats identity and runtime selection as separate configuration:

```toml
[sidecar.authority]
agent_id = "agt_01j0000000e008000000000001"

[run]
profile = "codex"
```

`agent_id` is the stable Authority-registered `agt_` TypeID used for capability
issuance, audit attribution, component metadata, `FIRMA_AGENT_ID`, and
`x-firma-agent`. `profile` selects local execution behavior and is exposed as
`FIRMA_RUN_PROFILE` and `x-firma-profile`; it is not sent as the registered
identity.

New local scaffolds generate an `agt_` TypeID backed by UUIDv7. Remote operators
copy the agent ID returned by FirmaTeam registration and use
`firma config --agent-id <agent-id>`. Raw UUIDs and other prefixes are rejected.

`firma run` never generates or edits identity in an existing config. A missing
field, a legacy profile value such as `codex`, or another invalid agent ID fails
closed before backend or component startup. Migrate with
`firma config --agent-id <agent-id>` and retain the profile under
`[run].profile`.

## Config-Relative Resource Resolution

A resource field holding a **relative** path resolves under the resolved
`config_dir` (the parent of the discovered `firma.toml`), not the working
directory. This is consistent whether the value is the serde default or an
operator-set relative path — relative always means "relative to the config
file's directory". **Absolute** paths are used verbatim. An **empty** value
is left untouched so the validator can reject it. Runtime/state paths stay
in the state/runtime dir and are never re-based.

For `[authority]`, `FIRMA_AUTHORITY_*` environment overrides are applied
_after_ re-basing, so an env-supplied path is preserved exactly as written
(a relative env value is **not** re-based against `config_dir`).

Every config-declared resource path re-bases, except the two
state-managed paths listed further below. The re-basing fields are:

| Field                               | Relative value resolves under |
| ----------------------------------- | ----------------------------- |
| sidecar `policy.dir`                | `<config_dir>/<value>`        |
| sidecar `mapping.rules_path`        | `<config_dir>/<value>`        |
| sidecar `mapping.rules_paths[]`     | `<config_dir>/<value>`        |
| sidecar `authority.public_key_path` | `<config_dir>/<value>`        |
| sidecar `capability_seed.paths[]`   | `<config_dir>/<value>`        |
| sidecar `audit.file_path`           | `<config_dir>/<value>`        |
| sidecar `audit.signing_key_path`    | `<config_dir>/<value>`        |
| authority `policy_dir`              | `<config_dir>/<value>`        |
| authority `issuance_policy_dir`     | `<config_dir>/<value>`        |
| authority `schema_path`             | `<config_dir>/<value>`        |
| authority `key_file`                | `<config_dir>/<value>`        |

State-managed paths are explicitly excluded from re-basing and stay in the
state/runtime dir:

| Field                       | Resolves to                               |
| --------------------------- | ----------------------------------------- |
| sidecar `ca.dir`            | as configured (default `./firma-ca/`)     |
| authority `revocation_file` | as configured (default `revocations.txt`) |
| sockets, pid, listen, logs  | state/runtime dir                         |

> **See also**: `examples/demo/firma.toml` is the canonical
> end-to-end reference. `just demo-ci` boots the sidecar against it
> and gates merges via the `demo-e2e` GitHub Actions workflow.

## Minimal Configuration

An empty file is valid. Defaults are applied for every section:

```toml
# Empty config uses all defaults.
# Interceptor: HTTP proxy on 0.0.0.0:8080
# Policy dir: ./policies/
# CA dir: ./firma-ca/
# Mapping rules: mapping-rules.toml
```

## Full Example

```toml
[interceptor]
mode = "http_proxy"
listen_addr = "127.0.0.1:9090"
drain_timeout = "15s"
max_request_body_bytes = 4194304
# socket_path = "/tmp/firma.sock"

[interceptor.connect_relay]
setup_timeout = "10s"
session_max = "10m"

[interceptor.https_mitm]
enabled = true
intercept_hosts = ["api.openai.com", "api.supabase.com", "*.resend.com"]
bypass_hosts = ["status.openai.com"]
strict_hosts = ["api.openai.com"]
cert_ttl = "24h"
cert_cache_capacity = 1024

[policy]
dir = "/etc/firma/policies"
authority_url = "https://authority.example.com"

[ca]
dir = "/etc/firma/ca"

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
session_state_capacity = 8192
session_state_backend = "lru"

[connector]
default_timeout_ms = 15000

[[connector.hosts]]
host = "api.openai.com"
rps = 60
burst = 10
timeout_ms = 60000

[authority]
connect_timeout = "10s"
reconnect_min_backoff = "250ms"
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

| Field                    | Type        | Default        | Description                           |
| ------------------------ | ----------- | -------------- | ------------------------------------- |
| `mode`                   | string      | `http_proxy`   | `http_proxy`, `grpc`, `unix_socket`   |
| `listen_addr`            | socket addr | `0.0.0.0:8080` | TCP address for HTTP proxy and gRPC   |
| `socket_path`            | path        | none           | Required when mode is `unix_socket`   |
| `drain_timeout`          | u64         | `30`           | Shutdown drain timeout in seconds     |
| `max_request_body_bytes` | usize       | `4194304`      | Max inbound request body size (bytes) |

Validation:

- `drain_timeout` must be greater than `0`.
- `max_request_body_bytes` must be greater than `0`.
- On Unix, `socket_path` must be set and non-empty when mode is `unix_socket`.

### `[interceptor.connect_relay]`

Timeout controls for CONNECT tunnel and HTTPS MITM relay sessions.

| Field           | Type | Default | Description                                              |
| --------------- | ---- | ------- | -------------------------------------------------------- |
| `setup_timeout` | u64  | `10`    | Timeout for CONNECT upgrade and upstream setup/handshake |
| `session_max`   | u64  | `600`   | Hard cap for an individual CONNECT/MITM session lifetime |

Validation:

- `setup_timeout` must be greater than `0`.
- `session_max` must be greater than `0`.

### `[interceptor.https_mitm]`

Optional TLS MITM controls for HTTPS `CONNECT` traffic in `http_proxy` mode.
Defaults are MITM-enabled with a curated common API host list. Hosts not matched
by `intercept_hosts` stay in transparent CONNECT tunnel mode (destination-level
enforcement only).

| Field                 | Type         | Default                  | Description                                         |
| --------------------- | ------------ | ------------------------ | --------------------------------------------------- |
| `enabled`             | bool         | `true`                   | Enables MITM for hosts matched by `intercept_hosts` |
| `ca_cert_path`        | path         | none                     | Optional explicit CA certificate path               |
| `ca_key_path`         | path         | none                     | Optional explicit CA private key path               |
| `intercept_hosts`     | list<string> | curated common API hosts | Host patterns to intercept (`*` or `*.example.com`) |
| `bypass_hosts`        | list<string> | `[]`                     | Host patterns to force CONNECT tunnel mode          |
| `strict_hosts`        | list<string> | `[]`                     | Host patterns that must be intercepted              |
| `cert_ttl`            | u64          | `86400`                  | Leaf certificate cache TTL in seconds               |
| `cert_cache_capacity` | usize        | `1024`                   | Maximum number of cached leaf certificates          |

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
- If `enabled = true`, `cert_ttl` and `cert_cache_capacity` must be
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
- This includes plain HTTP requests and HTTPS CONNECT destinations that are not
  explicitly blocked by mapping/policy.
- Intercepted hosts still flow through full intent normalization + policy +
  audit.
- `strict_hosts` fail closed if MITM setup cannot be established.

Audit/log visibility note:

- Hosts outside `intercept_hosts` are handled as CONNECT tunnel flows. They are
  still governed, but without decrypted L7 request details.
- For clearer counterpart observability (action/resource-rich audit + explicit
  sidecar handling logs), include target hosts in `intercept_hosts` and keep
  them out of `bypass_hosts`.

#### Quick Troubleshooting

- Sidecar is healthy, but you see no traffic logs/audit for a command:
  - In `http_proxy` mode, sidecar only governs traffic that is actually routed
    to its proxy listener.
  - Verify client env:
    - `HTTP_PROXY=http://<sidecar-listen-addr>`
    - `HTTPS_PROXY=http://<sidecar-listen-addr>`
    - `ALL_PROXY=http://<sidecar-listen-addr>`
  - If you use `firma run`, use the wrapper path so bridge/proxy wiring is
    injected automatically.
  - If the client reports `Failed to connect to 127.0.0.1:18080`, that is a
    local proxy-bridge reachability failure before sidecar mediation. In that
    case, no sidecar deny/allow record is expected for that request.
  - With interactive agent CLIs, this can also happen when a command is
    explicitly executed outside the governed sandbox path; the command may
    inherit proxy env pointing to `127.0.0.1:18080` even though the sandbox
    bridge is not in that execution context.
- If you see `TokenExpired` denies, re-issue a capability for the same
  `session_id` and restart sidecar when using `[capability_seed]`. For local
  workflows use:
  - `examples/firma-run/local/renew-capability.sh --session-id "$FIRMA_RUN_SESSION_ID"`
  - `pwsh ./examples/firma-run/local/renew-capability.ps1 -SessionId $env:FIRMA_RUN_SESSION_ID`

- You see `curl` timeout / agent network timeout, but no obvious deny:
  - Check audit for `action=network.connect` on the target host. This confirms
    policy allowed the destination-level CONNECT.
  - Check logs for `CONNECT relay failed after policy allow` or
    `MITM CONNECT relay failed after policy allow`. These include
    `failure_class` (`timeout`, `refused`, `reset`, `tls_handshake`, `dns`) so
    operators can distinguish policy allow from upstream network failure.
  - Add the host to `intercept_hosts` to get richer L7 policy/audit context.
  - For `firma run --profile codex`, wrapper defaults inject:
    - `--sandbox workspace-write`
    - `--ask-for-approval never`
      This keeps tool commands on the governed path by default and avoids
      out-of-sandbox runs that bypass sidecar mediation.

- You want clear “blocked by policy” signals:
  - Look for:
    - `HTTP request denied by guard policy`
    - `MITM HTTPS request denied by guard policy`
    - `CONNECT denied by guard policy`
    - `websocket upgrade denied by guard policy`
  - These include reason/detail and are the primary operators signals for
    config/policy tuning.

- You want explicit audit trace when CONNECT was allowed but failed later:
  - Sidecar emits a follow-up ABORT audit record with:
    - `action=network.connect`
    - `resource=<host>/`
    - `deny_reason` prefixed with `CONNECT_RELAY_FAILURE: ...`

- You see `websocket MITM relay closed by peer (expected shutdown)`:
  - This is normal when clients close without TLS `close_notify` (for example
    interactive CLI shutdown). It is informational, not a policy failure.

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
- This applies to both plain HTTP requests and HTTPS CONNECT destinations.
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

| Field                    | Type   | Default | Description                                      |
| ------------------------ | ------ | ------- | ------------------------------------------------ |
| `session_state_capacity` | usize  | `8192`  | Maximum active sessions retained in the cache    |
| `session_state_backend`  | string | `lru`   | `lru` or file-backed `persistent` storage        |
| `session_state_path`     | path   | none    | Optional JSONL path for the `persistent` backend |

`session_state_capacity` must be at least `1`.

Policy-bundle freshness is not configured in this Sidecar section. The
Authority embeds `[authority].bundle_ttl` in each streamed bundle,
periodically refreshes it, and Stage 2 denies with `PolicyBundleStale` if that
advertised deadline expires. Cedar evaluation has no user-configurable timeout.

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
`authority.url` is set; when unset the sidecar runs in dev
mode and this section is ignored.

| Field                                  | Type     | Default   | Description                                                                                                                 |
| -------------------------------------- | -------- | --------- | --------------------------------------------------------------------------------------------------------------------------- |
| `connect_addr`                         | address  | none      | Advanced physical TCP destination; `url` remains the logical HTTP and TLS origin                                            |
| `connect_timeout`                      | duration | `"10s"`   | Connection timeout for the tonic channel                                                                                    |
| `reconnect_min_backoff`                | duration | `"250ms"` | Minimum reconnect backoff                                                                                                   |
| `reconnect_max_backoff_secs`           | u64      | `30`      | Maximum reconnect backoff                                                                                                   |
| `revocation_readiness_grace_ms`        | u64      | `500`     | Grace period after revocation stream opens before readiness                                                                 |
| `revocation_fail_closed_on_disconnect` | bool     | `false`   | Flip revocation readiness back to false when the stream drops                                                               |
| `public_key_path`                      | path     | none      | Authority Ed25519 public key. Required when `[capability_seed].paths` is non-empty so the sidecar can verify seeded tokens. |
| `credentials`                          | section  | none      | Optional Sidecar PSK credentials sent on every Authority RPC.                                                               |

Validation:

- `connect_timeout`, `reconnect_min_backoff`, and
  `reconnect_max_backoff_secs` must all be greater than `0`.
- `connect_addr` requires `url` and must use a nonzero port. For plaintext
  URLs, the insecure-remote check uses this physical address when present.
- `reconnect_max_backoff_secs * 1000` must be ≥
  `reconnect_min_backoff`.
- When `credentials` is present, `workspace_id` and `sidecar_id`
  must be non-empty, and exactly one PSK source must be configured.

#### `[authority.credentials]`

Use this section when connecting a Sidecar to an Authority that requires a
pre-shared key. The PSK is issued by the Authority operator. It is resolved once
at startup, kept in memory, and sent on `IssueCapability`,
`WatchPolicyBundle`, and `WatchRevocations`.

```toml
[authority.credentials]
workspace_id = "ws-acme"
sidecar_id = "sc-eu-1"

# exactly one:
pre_shared_key_env = "FIRMA_SIDECAR_PSK"
# pre_shared_key_path = "/run/secrets/firma-sidecar-psk"
```

`pre_shared_key_path` is resolved relative to the config file directory when it
is not absolute. File values have trailing newlines trimmed. If the section is
absent, the Sidecar sends no credentials and remains compatible with the local
Mini Authority path.

Behavior notes:

- Requests are denied with `POLICY_BUNDLE_NOT_READY` until the first
  bundle has been applied and `REVOCATION_CACHE_NOT_READY` until the
  revocation stream has either received its first event or the grace
  period has elapsed — whichever happens first.
- The policy bundle TTL carried in each `PolicyBundleUpdate` is authoritative.
  When the deadline elapses without a refresh, Stage 2 denies with
  `PolicyBundleStale`.
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
produced by `firma authority issue` (see `docs/cli.md`). The sidecar
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

> **Deprecated.** `[capability_seed]` is superseded by per-session capabilities
> minted live by `firma run`, written to
> `$XDG_RUNTIME_DIR/firma/capabilities/<sandbox_id>.toml`. Operator-configured
> seed paths still load but emit a deprecation warning at sidecar startup.
> Removal is scheduled for a later release once examples and install scripts
> migrate.

### `[local_exec]`

Optional local-exec governance endpoint. When present, the sidecar binds an
additional Unix domain socket that `firma-run` clients contact for pre-execution
governance decisions on local tool invocations. If the section is absent, the
endpoint is not started.

This is the server-side counterpart to the `sidecar_local_exec` section in the
`firma-run` profile config.

| Field            | Type   | Default | Description                                                                             |
| ---------------- | ------ | ------- | --------------------------------------------------------------------------------------- |
| `socket_path`    | path   |         | **Required.** Absolute path to the Unix domain socket file.                             |
| `default_action` | string | `deny`  | Policy for fresh requests: `allow`, `deny`, or `pending_hitl` (HITL approval required). |
| `token_ttl_secs` | u64    | `300`   | Approval token lifetime in seconds. Must be > 0.                                        |
| `retry_after_ms` | u64    | `500`   | Suggested retry interval returned to `firma-run` in `pending_hitl` responses (ms). > 0. |

Validation:

- `socket_path` must be an absolute path.
- `token_ttl_secs` and `retry_after_ms` must be greater than `0`.

Example:

```toml
[local_exec]
socket_path = "/run/firma/local-exec.sock"
default_action = "pending_hitl"
token_ttl_secs = 300
retry_after_ms = 500
```

The `pending_hitl` action triggers the HITL approval token flow: `firma-run`
receives a `pending_hitl` response with a single-use, short-lived `approval_token`;
for `async_token` mode, `firma-run` retries internally with the token until
`allow|deny` or timeout. See the Local-Exec Governance section in
`docs/architecture/command-governance-local-exec-contract.md` for the full protocol.

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
