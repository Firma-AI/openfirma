# Configuration Reference

Every subcommand reads one shared, sectioned `firma.toml`. There is exactly
**one** schema. A single file holds top-level `[authority]`, `[sidecar.*]`
(`[sidecar.interceptor]` / `[sidecar.policy]` / `[sidecar.ca]` /
`[sidecar.audit]`), and `[run]`. Commands consume the sections they need. A required section that
is missing fails closed; diagnostic or optional consumers can inspect multiple
sections or continue without an optional section.

## Configuration resolution

OpenFirma selects one unified configuration file in this order:

1. explicit `--config <path>`;
2. `FIRMA_CONFIG`; then
3. the nearest `.firma/firma.toml`, found by walking up from the current
   directory.

The first selected file wins. OpenFirma does not field-merge multiple
configuration files. A selected file must be readable and valid TOML, and
omitted schema fields receive their documented defaults.

After loading the selected `[authority]` section, Authority applies its
documented `FIRMA_AUTHORITY_*` environment overlays. The Sidecar has no
profile-style inheritance: only its documented explicit CLI options override
fields from the selected `[sidecar]` section. Dedicated Sidecar launch and
autostart template inputs select one Sidecar source; they do not add another
field-merge layer.

Run alone has profile inheritance. It resolves the built-in profile, then
`[run.defaults]`, then the selected `[run.profiles.<name>]`, and finally
supplied CLI profile values. Higher layers override lower layers according to
the shape rules below.

Configuration is validated at startup. Invalid fields cause the affected
binary to exit before accepting requests.

## Scalar syntax

Duration settings use compact unit-bearing strings such as `"250ms"`, `"30s"`,
`"10m"`, and `"1h"`. Byte-size settings use unit-bearing strings such as
`"4 MiB"` and `"10MB"`. Counts, capacities, and rates remain numeric.

The Sidecar interceptor body limits (`max_request_body_size`,
`max_decompressed_body_size`, and `total_body_budget`) and audit
`buffer_max_size` and `wal_max_size` must be strictly greater than zero; a zero
such as `"0 B"` fails while the config is being deserialized.

Authority `max_ttl` and `bundle_ttl` must be strictly greater than zero. A zero
maximum would create immediately expired capabilities, while a zero bundle
lifetime would create immediately stale policy.

### Non-zero duration controls

Timeout, deadline, wait, retry, and session-lifetime controls must use
unit-bearing durations strictly greater than zero; exact zero values such as
`"0s"`, `"0ms"`, or `"0ns"` fail while the config is being deserialized. This
applies to:

- `[sidecar.secret_gateway]` `connection_timeout` and `operation_timeout`;
- Run profile `sidecar_local_exec.timeout` and `hitl_max_wait`;
- `[sidecar.authority]` `connect_timeout`, `reconnect_min_backoff`, and
  `reconnect_max_backoff`;
- `[sidecar.audit]` `replay_ack_timeout` and `wal_request_timeout`;
- `[sidecar.interceptor]` `drain_timeout`;
- `[sidecar.interceptor.connect_relay]` `setup_timeout` and `session_max`;
- `[sidecar.connector]` `default_timeout` and each host `timeout`; and
- `[sidecar.local_exec]` `retry_after` (which must also be at least 1 ms because
  its wire representation uses whole milliseconds).

TTL, retention, and grace durations have field-specific semantics instead of
inheriting this general non-zero duration rule. Authority `max_ttl` and
`bundle_ttl` and `sidecar.local_exec.token_ttl` are also strictly non-zero,
because zero would make their outputs immediately expired or stale; a zero
`token_ttl` fails while the config is being deserialized. Run profile
`capability.grace`, `sidecar.authority.revocation_readiness_grace`, and
`sidecar.interceptor.https_mitm.cert_ttl` each have their own validation. For
example, a zero revocation readiness grace is valid and only means the Sidecar
warns at once when a connection has not yet delivered a revocation set;
readiness still waits for an applied set.

Unknown keys are rejected recursively rather than ignored. The only top-level
keys are `authority`, `sidecar`, and `run`; nested objects and tagged variants
are strict as well. Dynamic labels such as credential names, executable-policy
names, and Run profile names remain open, but every value under those labels
must match its schema. Firma validates all Run defaults and profiles while
parsing the file, including profiles that are not selected, so a typo or an
unsupported `backend` anywhere fails startup. Configure process logging with
`--log-filter` / `FIRMA_LOG_FILTER`.

### Run capability sources

Capability sources use a tagged `capability.source` table. A file source names
canonical signed capability seed TOML produced by `firma authority issue`:

```toml
[run.profiles.codex.capability.source]
kind = "file"
path = "capability.toml"
```

Use `kind = "disabled"` without `path` to disable the source.
For a file source, Run parses the complete seed before preparing the sandbox,
exports only `raw_token` as `FIRMA_CAPABILITY_TOKEN`, and preserves the
configured path as `FIRMA_CAPABILITY_FILE`. For local Sidecar autostart, the
file and its resolved target must stay beneath the selected
`<state-dir>/capabilities/` directory; the Sidecar reads only the resolved path
and watches both contained parent directories. A pre-managed external Sidecar
owns its runtime state and seed list independently.

#### Migrating a bare-token capability file

Earlier releases accepted a file holding only the raw `v4.public....` token, for
either `path` or `firma run --capability-file`. Such a file now fails closed
before launch, and so does a Sidecar configured to load it:

```text
capability seed '/etc/firma/capability.toml' is not canonical CapabilitySeed TOML: key with no value, expected `=`
```

A bare token carries none of the claims the canonical shape requires, so there
is nothing to rewrite. Re-issue the capability and point at the new file:

```bash
firma authority issue \
  --agent-id agt_01j0000000e008000000000001 \
  --session-id <session-id> \
  --action communication.external.send \
  --output capability.toml
```

The same applies to a seed that was hand-edited to carry extra fields such as
operator notes: the loader accepts exactly the fields `firma authority issue`
writes, and names any additional one in its error.

### Run executable policies

Executable launch policies are keyed by executable name. For Codex:

```toml
[run.profiles.codex.executable_policies.codex]
approval_policy = "on-request"
```

## Scaffolded Example

`firma config` writes one sectioned `firma.toml`. Policy and mapping paths stay
relative to the config file, and the artifact files the command generates —
signing keys, revocations, TLS material, audit log and key, MITM CA — are **not**
named at all. Each has a default that resolves to the position the material was
just written to, so naming it would only pin the file to this machine. The
shape is:

```toml
[authority]
mapping_rules_paths = ["mapping-rules.toml"]
listen_addr = "127.0.0.1:50051"
policy_dir = "policies/"
issuance_policy_dir = "issuance-policies/"
max_ttl = "1h"
bundle_ttl = "30s"

[sidecar.interceptor]
mode = "http_proxy"
listen_addr = "127.0.0.1:8080"

[sidecar.authority]
agent_id = "agt_01j0000000e008000000000001"
url = "https://127.0.0.1:50051"
```

The connected Sidecar receives mappings only in the mini-authority's snapshot;
the producer list in `[authority]` owns them.

Every omitted key remains settable as an override, and an explicit value always
wins. `--state-dir` selects the root the defaults resolve against at scaffold
time; the Authority and Sidecar resolve the same root at startup from
`FIRMA_STATE_DIR` or the platform runtime directory, so export `FIRMA_STATE_DIR`
when you scaffold somewhere other than the default.

### State-directory defaults

| Key                                        | Unset resolves to                                                                             |
| ------------------------------------------ | --------------------------------------------------------------------------------------------- |
| `authority.key_file`                       | `<state_dir>/authority.key`                                                                   |
| `authority.revocation_file`                | `<state_dir>/revocations.txt`                                                                 |
| `authority.tls_cert_path` / `tls_key_path` | `<state_dir>/tls/authority.{crt,key}` — TLS stays off when neither file exists                |
| `sidecar.ca.dir`                           | `<state_dir>/generated-firma-ca`                                                              |
| `sidecar.audit.file_path`                  | `<state_dir>/audit.jsonl`, with the `file` sink                                               |
| `sidecar.audit.signing_key_path`           | `<state_dir>/audit.key`, unless `signing_key_env` is set                                      |
| `sidecar.authority.public_key_path`        | `<state_dir>/authority.pub`, when that file exists                                            |
| `sidecar.authority.ca_cert_paths`          | `[<state_dir>/tls/authority-ca.crt]`, when that file exists and the Authority is on this host |

The Authority trust anchors and the Authority's own TLS pair are adopted only when
the material is actually present, so a deployment that never generated them
keeps today's behavior — plaintext gRPC and a reject-all token verifier —
instead of failing on a file nobody wrote. A half-generated Authority TLS pair
is rejected rather than silently downgraded to plaintext, and an Authority that
finds no TLS material logs a warning before serving plaintext.

The state directory's Authority CA belongs to the Authority that `firma config`
set up on this host, so it is adopted only when `sidecar.authority.url` names
this host — `localhost` or a loopback IP, with `connect_addr`, if set, on
loopback too. An `https://` Authority on this host with no CA there, in
`ca_cert_paths` is rejected at startup, since no public CA certifies a
loopback name. An `https://` Authority elsewhere with no CA named is verified
against the platform's trusted roots, which `SSL_CERT_FILE` and
`SSL_CERT_DIR` override; `disable_platform_roots = true` refuses that
fallback and is rejected at startup unless a CA is named. `firma config`
writes `ca_cert_paths` with the single CA it is given, warning when that
replaces a longer hand-written list, and removes it, with
`disable_platform_roots`, when none is.
Earlier releases
adopted `tls/authority-ca.crt` for any Authority: a deployment whose Authority
on another host presents a certificate issued from that CA
(`firma authority bootstrap-tls --hosts <name>`) now logs a warning that the
file is skipped, and needs `ca_cert_paths` to list it.

**The state directory is therefore a trust root** for two files:
`authority.pub` (which capability tokens are verified against), adopted when
the config names none, and `tls/authority-ca.crt` (which the Authority's TLS
identity is verified against), adopted as above. Keep the state
directory private — `firma config` creates it mode 0700 — and pin the paths
explicitly if it is shared.

### Migrating an existing config

Defaults changed, so a hand-written config that relied on the old ones behaves
differently:

| Key                         | Old default when unset                               | New default                      |
| --------------------------- | ---------------------------------------------------- | -------------------------------- |
| `authority.key_file`        | `firma-authority.key`, re-based to `<config_dir>`    | `<state_dir>/authority.key`      |
| `authority.revocation_file` | `revocations.txt`, relative to the working directory | `<state_dir>/revocations.txt`    |
| `sidecar.ca.dir`            | `./firma-ca/`, relative to the working directory     | `<state_dir>/generated-firma-ca` |

Set the key explicitly to keep the old location. `sidecar.ca.dir` matters most:
a new directory means a **new MITM CA**, so anything that already trusts the old
one stops trusting intercepted TLS until it is re-imported.

The `[sidecar.*]` tables map onto the per-section reference below
(`[sidecar.interceptor]` documents the same fields as
[`[sidecar.interceptor]`](#interceptor), `[sidecar.policy]` as
[`[sidecar.policy]`](#policy), and so on). `[authority]` is the
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

Local scaffolds generate an `agt_` TypeID backed by UUIDv7. Remote operators
copy the agent ID returned by FirmaTeam registration and use
`firma config --agent-id <agent-id>`.

`firma run` never generates or edits identity in an existing config. A missing
or invalid agent ID fails closed before backend or component startup.

## Run profile layering

The [configuration resolution](#configuration-resolution) order applies these
shape rules at each Run profile layer:

| Shape                 | Rule                                                      |
| --------------------- | --------------------------------------------------------- |
| Scalar, enum, boolean | Omitted inherits; a present value replaces                |
| Nested patch          | Independently overridable fields merge field-by-field     |
| List                  | Omitted inherits; a present list replaces; `[]` clears    |
| Map                   | Omitted inherits; empty clears; non-empty merges by key   |
| Supplied CLI value    | Replaces the resolved profile value at highest precedence |

Repeat inherited members in a higher non-empty list when they must remain.
Maps do not support deleting one inherited key: override that key, retain the
map, or clear the whole map. Matching map values that are nested patches merge
field-by-field.

Security-relevant sharp edges:

- Clearing `env_set` removes all built-in hardening and proxy-bypass values,
  including `NO_PROXY` / `no_proxy`.
- A policy set that authorizes none of the action classes a run requests fails
  closed with Authority reason `NO_AUTHORIZED_ACTIONS` before launch. Which
  capabilities a session holds is not configurable here: every mint requests all
  action classes and the policy set applied to the agent decides the grant.
- A resolved `seccomp_policy` requires both `source_policy_path` and
  `artifact_dir`.
- `enforce_known_executables = true` requires a non-empty
  `allowed_executables` list.
- `--allow-non-structural` and `FIRMA_RUN_ALLOW_NON_STRUCTURAL` are explicit
  enable-only safety opt-ins outside profile inheritance; when omitted, they do
  not override the resolved profile.

Inspect the result before launch:

```console
firma run --profile generic --print-effective-config -- echo hi
```

## The Workspace Mount

`firma run` binds one directory read-write for the agent: the **project root**,
meaning the directory that holds the `.firma/` the config was loaded from. That
is derived from where the config file is, not from the directory you invoke
`firma run` in — so running from a subdirectory still gives the agent the whole
project.

Because it is derived, `firma config` does not write it. An ordinary scaffolded
`firma.toml` has no `[[run.profiles.<profile>.mounts]]` block at all, and names
no path from the machine that generated it.

Two cases are still recorded explicitly, because the derivation would not
reproduce them:

- `--workspace <dir>` pointing somewhere other than the project root.
- A config whose directory is not named `.firma`, or whose project root would
  be `$HOME` or the filesystem root. Those roots are refused: `$HOME` is far
  wider than a project, and the sensitive-path overlay covers only a fixed
  suffix list.

Adding any `mounts` entry replaces the derived default entirely, so list every
path the agent needs. Re-running `firma config` drops a workspace mount it can
derive and leaves mounts you added by hand alone.

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
(a relative env value is **not** re-based against `config_dir`). The TTL
overrides are `FIRMA_AUTHORITY_MAX_TTL` and `FIRMA_AUTHORITY_BUNDLE_TTL`; they
use the same compact duration syntax and validation as the corresponding TOML
fields.

Resource paths resolve relative to the containing `firma.toml`. This includes
Authority mapping files; Authority client mTLS files and credential secret files;
and Run file-provided mount sources, seccomp policies, capability files, and
capability keys in both defaults and every profile.

| Field                                                                                     | Relative value resolves under |
| ----------------------------------------------------------------------------------------- | ----------------------------- |
| `sidecar.policy.dir`                                                                      | `<config_dir>/<value>`        |
| `authority.mapping_rules_paths[]`                                                         | `<config_dir>/<value>`        |
| `sidecar.authority.public_key_path`, `ca_cert_paths[]`, mTLS, and credential secret files | `<config_dir>/<value>`        |
| `sidecar.audit.file_path`                                                                 | `<config_dir>/<value>`        |
| `sidecar.audit.signing_key_path`                                                          | `<config_dir>/<value>`        |
| `authority.policy_dir`                                                                    | `<config_dir>/<value>`        |
| `authority.issuance_policy_dir`                                                           | `<config_dir>/<value>`        |
| `authority.schema_path`                                                                   | `<config_dir>/<value>`        |
| `authority.key_file`                                                                      | `<config_dir>/<value>`        |
| Run mount sources, seccomp paths, capability files/keys                                   | `<config_dir>/<value>`        |

Runtime/state paths, endpoints, sandbox mount targets, and WAL, session,
revocation, and `sidecar.ca.dir` paths are not re-based. Mask-home values are
home-relative, executable allowlist entries must be absolute paths to existing
files and are canonicalized when loaded, and CLI path arguments remain verbatim.

| Field                       | Resolves to                                                                                                         |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| `sidecar.ca.dir`            | as configured (default `<state>/generated-firma-ca`)                                                                |
| `authority.revocation_file` | as configured — an explicit relative value stays relative to the working directory — else `<state>/revocations.txt` |
| sockets, pid, listen, logs  | state/runtime dir                                                                                                   |

Fields left unset resolve against the state directory (`--state-dir`, else
`FIRMA_STATE_DIR`, else the platform runtime directory) instead — see
[State-directory defaults](#state-directory-defaults) for the full table.

> **See also**: `examples/demo/firma.toml` is the canonical
> end-to-end reference.

## Minimal Configuration

Every field has a default except two required inputs: a Sidecar needs its
Authority endpoint, and an Authority needs at least one mapping file.

```toml
# Interceptor: HTTP proxy on 0.0.0.0:8080
# Policy dir: ./policies/
# CA dir: <state>/generated-firma-ca
# Audit log: <state>/audit.jsonl, signed with <state>/audit.key

[authority]
mapping_rules_paths = ["mapping-rules.toml"]

[sidecar.authority]
url = "https://127.0.0.1:50051"
```

## Full Example

```toml
[authority]
mapping_rules_paths = ["/etc/firma/rules.toml"]

[sidecar.interceptor]
mode = "http_proxy"
listen_addr = "127.0.0.1:9090"
drain_timeout = "15s"
max_request_body_size = "4 MiB"
# socket_path = "/tmp/firma.sock"

[sidecar.interceptor.connect_relay]
setup_timeout = "10s"
session_max = "10m"

[sidecar.interceptor.https_mitm]
enabled = true
intercept_hosts = ["api.openai.com", "api.supabase.com", "*.resend.com"]
bypass_hosts = ["status.openai.com"]
strict_hosts = ["api.openai.com"]
cert_ttl = "24h"
cert_cache_capacity = 1024

[sidecar.policy]
dir = "/etc/firma/policies"

[sidecar.ca]
dir = "/etc/firma/ca"

[sidecar.credentials.openai]
mode = "basic"
target_host = "api.openai.com"
header = "Authorization"
value_from_env = "OPENAI_API_KEY"
prefix = "Bearer "

[sidecar.credentials.stripe]
mode = "vault"
target_host = "api.stripe.com"
header = "Authorization"
secret_path = "/run/secrets/stripe_token"
prefix = "Bearer "

[sidecar.constraint_enforcement]
session_state_capacity = 8192
session_state_backend = "lru"

[sidecar.connector]
default_timeout = "15s"

[[sidecar.connector.hosts]]
host = "api.openai.com"
rps = 60
burst = 10
timeout = "1m"

[sidecar.authority]
url = "https://authority.example.com"
connect_timeout = "10s"
reconnect_min_backoff = "250ms"
reconnect_max_backoff = "30s"
revocation_readiness_grace = "500ms"
revocation_fail_closed_on_disconnect = false

[sidecar.revocation]
capacity = 1000000
fpr = 0.0001
lru_capacity = 100000

[sidecar.audit]
sink = "grpc"
file_path = "/var/log/firma/audit.jsonl"
grpc_url = "https://audit.example.com"
buffer_path = "/var/lib/firma/audit-buffer.jsonl"
buffer_max_size = "100 MiB"
signing_key_path = "/etc/firma/audit.pem"
# signing_key_env = "FIRMA_AUDIT_SIGNING_KEY"
```

## Sections

### `[sidecar.interceptor]`

Selects the interception mode and transport-specific parameters.

| Field                   | Type        | Default        | Description                         |
| ----------------------- | ----------- | -------------- | ----------------------------------- |
| `mode`                  | string      | `http_proxy`   | `http_proxy`, `grpc`, `unix_socket` |
| `listen_addr`           | socket addr | `0.0.0.0:8080` | TCP address for HTTP proxy and gRPC |
| `socket_path`           | path        | none           | Required when mode is `unix_socket` |
| `drain_timeout`         | duration    | `"30s"`        | Shutdown drain timeout              |
| `max_request_body_size` | byte size   | `"4 MiB"`      | Max inbound request body size       |

Validation:

- `drain_timeout` and `max_request_body_size` must be greater than zero.
- On Unix, `socket_path` must be set and non-empty when mode is `unix_socket`.

### `[sidecar.interceptor.connect_relay]`

Timeout controls for CONNECT tunnel and HTTPS MITM relay sessions.

| Field           | Type     | Default | Description                                              |
| --------------- | -------- | ------- | -------------------------------------------------------- |
| `setup_timeout` | duration | `"10s"` | Timeout for CONNECT upgrade and upstream setup/handshake |
| `session_max`   | duration | `"10m"` | Hard cap for an individual CONNECT/MITM session lifetime |

Validation:

- `setup_timeout` and `session_max` must be greater than zero.

### `[sidecar.interceptor.https_mitm]`

Optional TLS MITM controls for HTTPS `CONNECT` traffic in `http_proxy` mode.
Interception is on by default for **every** host, and every host is strict, so
a host that cannot be intercepted is denied rather than tunnelled uninspected.
Exempt the endpoints that cannot be intercepted through `bypass_hosts`; a
bypassed host stays in transparent CONNECT tunnel mode with destination-level
enforcement only. Three cases need it:

- **Certificate pinning.** The client rejects the Sidecar's leaf certificate.
- **Upstream mTLS.** The endpoint wants a client certificate the Sidecar does
  not hold.
- **Anything tunnelled through `CONNECT` that is not TLS** — SSH via
  `ProxyCommand`, a database or SMTP tunnel, plaintext on port 443. A strict
  host refuses a non-TLS payload rather than relaying it, and every host is
  strict by default. The refusal is audited as `network.connect` with reason
  `FailClosed` and a detail naming the preface, so check audit before blaming
  the network.

| Field                 | Type         | Default | Description                                         |
| --------------------- | ------------ | ------- | --------------------------------------------------- |
| `enabled`             | bool         | `true`  | Enables MITM for hosts matched by `intercept_hosts` |
| `intercept_hosts`     | list<string> | `["*"]` | Host patterns to intercept (`*` or `*.example.com`) |
| `bypass_hosts`        | list<string> | `[]`    | Host patterns to force CONNECT tunnel mode          |
| `strict_hosts`        | list<string> | `["*"]` | Host patterns that must be intercepted              |
| `cert_ttl`            | duration     | `"1d"`  | Leaf certificate cache TTL                          |
| `cert_cache_capacity` | usize        | `1024`  | Maximum number of cached leaf certificates          |

Setting `intercept_hosts` or `strict_hosts` _replaces_ the default, so a file
that lists hosts explicitly narrows interception and will not pick up a later,
wider default. `firma config` therefore writes neither key, and strips
`enabled`, `intercept_hosts` and `strict_hosts` on every run — whoever wrote
them. A hand-written narrowing, including `enabled = false`, does not survive a
re-run; the removal only ever widens interception, which is the fail-closed
direction, but it is not a merge. `firma config` prints a warning naming the
keys it removed, so a narrowed host that starts hard-denying afterwards is
traceable to that run. Keep a host uninspected through `bypass_hosts`, which
`firma config` merges rather than replaces — and which it warns about when it
holds entries no selected mapping asks for, since a merged list never drops the
exemptions an earlier selection added.

Turning interception off entirely therefore goes through the same key:
`bypass_hosts = ["*"]` matches every host and is checked before interception, so
every tunnel is relayed uninspected. `enabled = false` and
`intercept_hosts = []` have the same runtime effect but are stripped by the next
`firma config` run, which leaves the machine intercepting again with only a
warning to show for it.

Validation:

- Host lists (`intercept_hosts`, `bypass_hosts`, `strict_hosts`) cannot contain
  empty patterns.
- Wildcard patterns are DNS-label-aware and only support:
  - `*` (match any host)
  - `*.example.com` (match subdomains only, not apex `example.com`)
- Wildcards inside labels (for example `api.*.com`) are rejected.
- Wildcard suffixes must contain at least two DNS labels (for example
  `*.com` is rejected).
- `enabled = true` with an explicitly empty `intercept_hosts` is accepted and
  treated as MITM disabled, not as an error: there is nothing to intercept.
- If `enabled = true`, `cert_ttl` and `cert_cache_capacity` must be
  greater than `0`.
- CA material has one location: `firma-ca.crt` and `firma-ca.key` under
  [`[sidecar.ca].dir`](#ca), created on first run. The individual file paths are
  not configurable, so whoever sets `dir` also controls where the private key
  lands. `firma run` relies on this: it pins `dir` to the per-run state entry,
  publishes the certificate to the sandbox, and keeps the key behind the
  control-plane mask.
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

The default covers every host rather than a curated provider list, because an
unlisted host is indistinguishable from an ungoverned one: traffic nobody
thought to enumerate would pass uninspected. Narrowing is an explicit operator
decision through `bypass_hosts`.

#### Practical operating modes

The sidecar supports progressive rollout patterns. Mappings always come from
the Authority, and its snapshots always protect unmatched traffic. A useful
mental model:

- `bypass_hosts` controls where you give up L7 visibility/enforcement; every
  other host is intercepted.
- Authority snapshots always protect unmatched traffic. Sidecars cannot override
  that posture or read local mapping files.

1. Targeted HTTPS inspection

Use when you need decrypted visibility for selected destinations. Explicit
Authority rules are still required for every admitted HTTP or CONNECT request.

```toml
[sidecar.interceptor.https_mitm]
enabled = true
intercept_hosts = ["api.anthropic.com", "platform.claude.com", "api.openai.com"]
strict_hosts = ["api.anthropic.com", "api.openai.com"]
```

Behavior:

- Unmapped HTTP requests and CONNECT destinations are denied.
- Intercepted hosts still flow through full intent normalization + policy +
  audit.
- `strict_hosts` fail closed if MITM setup cannot be established.

Audit/log visibility note:

- Every host is intercepted by default, so L7 request details are present
  unless a host sits in `bypass_hosts` or the file narrows `intercept_hosts`.
- A bypassed host is handled as a CONNECT tunnel flow. It is still governed,
  but without decrypted L7 request details, so keep a host out of
  `bypass_hosts` whenever you want action/resource-rich audit for it.

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
- You see `curl` timeout / agent network timeout, but no obvious deny:
  - Check audit for `action=network.connect` on the target host. This confirms
    policy allowed the destination-level CONNECT.
  - Check logs for `CONNECT relay failed after policy allow` or
    `MITM CONNECT relay failed after policy allow`. These include
    `failure_class` (`timeout`, `refused`, `reset`, `tls_handshake`, `dns`) so
    operators can distinguish policy allow from upstream network failure.
  - If the host is in `bypass_hosts`, remove it to get richer L7 policy/audit
    context — it is intercepted by default otherwise.
- A tunnel opens (`CONNECT` returns 200) and then dies with nothing relayed:
  - Check audit for a `network.connect` deny whose detail says
    `received non-TLS CONNECT preface`. Every host is strict by default, so a
    tunnel carrying something other than TLS is refused rather than relayed.
  - Add that host to `bypass_hosts` if it must stay reachable; it then tunnels
    with destination-level enforcement only.
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
[sidecar.interceptor.https_mitm]
enabled = true
intercept_hosts = ["api.anthropic.com", "platform.claude.com", "api.openai.com"]
strict_hosts = ["api.anthropic.com", "platform.claude.com", "api.openai.com"]
```

Behavior:

- Unmapped traffic is protected/denied unless explicit mapping/policy allows it.
- This applies to both plain HTTP requests and HTTPS CONNECT destinations.
- Intercepted strict hosts are fail-closed on MITM failures.

3. Destination-level governance only (no HTTPS decryption)

Use when you need host-level control but cannot run MITM for policy, legal, or
certificate-distribution reasons.

```toml
[sidecar.interceptor.https_mitm]
bypass_hosts = ["*"]
```

Behavior:

- Sidecar enforces at CONNECT destination level for HTTPS.
- No decrypted request path/body visibility for HTTPS.
- `bypass_hosts = ["*"]` rather than `enabled = false`: both switch
  interception off, but only this one survives a `firma config` re-run.

### `[sidecar.policy]`

Policy source settings.

| Field | Type | Default       | Description                         |
| ----- | ---- | ------------- | ----------------------------------- |
| `dir` | path | `./policies/` | Directory containing `.cedar` files |

Validation:

- `dir` must not be empty.

### `[sidecar.ca]`

Certificate authority directory.

| Field | Type | Default                      | Description                      |
| ----- | ---- | ---------------------------- | -------------------------------- |
| `dir` | path | `<state>/generated-firma-ca` | Directory containing CA material |

Validation:

- `dir` must not be empty.

### `[sidecar.credentials.<label>]`

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
[sidecar.credentials.openai]
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
[sidecar.credentials.stripe]
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

### Authority mapping inputs

`[authority].mapping_rules_paths` selects one or more mapping files, concatenated
in order. Omitted/empty lists and empty entries are rejected, including by
config-consuming offline Authority commands such as `firma authority issue`. A
selected file with no rules — empty, comment-only, or `rules = []` —
contributes nothing; when every selected file is like that, the Authority
publishes a deny-all snapshot. Sidecars require `[sidecar.authority].url` and
complete protected snapshots before readiness; endpoint-free mode is unsupported.

To upgrade, move former Sidecar primary/extra mapping paths to the Authority,
remove Sidecar mapping keys, and set the endpoint. There is no replacement for
`default_protected=false`. See the [mapping upgrade guide](../docs-site/src/content/docs/guides/extend-mapping.md).

### `[sidecar.constraint_enforcement]`

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

### `[sidecar.connector]`

Outbound dispatch defaults and per-host overrides.

| Field             | Type     | Default | Description                         |
| ----------------- | -------- | ------- | ----------------------------------- |
| `default_timeout` | duration | `"30s"` | Fallback dispatch timeout           |
| `hosts`           | list     | empty   | Per-host overrides, see table below |

Each `[[sidecar.connector.hosts]]` entry is required to state every field
explicitly — inheriting silent global defaults is not allowed.

| Field     | Type     | Required | Description                                |
| --------- | -------- | -------- | ------------------------------------------ |
| `host`    | string   | yes      | Target host (exact match)                  |
| `rps`     | u32      | yes      | Sustained token-bucket refill rate (req/s) |
| `burst`   | u32      | yes      | Token-bucket burst capacity                |
| `timeout` | duration | yes      | Dispatch timeout                           |

Validation:

- `default_timeout` must be greater than zero.
- Each host entry must set a non-empty `host`, and each of `rps`,
  `burst`, and `timeout` must be greater than zero.
- Duplicate `host` entries are rejected.

### `[sidecar.capability_seed]`

Configures canonical `CapabilitySeed` TOML loaded into Stage 1 at Sidecar
startup.

| Field        | Type       | Default | Description                                    |
| ------------ | ---------- | ------- | ---------------------------------------------- |
| `paths`      | path array | `[]`    | Existing canonical seed TOML files             |
| `hot_reload` | bool       | `true`  | Watch configured seeds and load valid rewrites |

Every configured file and its resolved target must stay beneath the selected
Sidecar runtime `<state-dir>/capabilities/` directory. The Sidecar canonicalizes
that directory, each existing seed, and each configured parent before reading or
registering a watcher. It reads only the resolved seed and watches only the two
contained parents. Traversal, external-parent, and symlink paths that cross the
boundary fail startup. An empty `paths` list does not require the directory to
exist.

### `[sidecar.authority]`

Authority endpoint and tuning for the background Authority stream clients
(`WatchPolicyBundle`, `WatchRevocations`). Every Sidecar requires `url`: the
Authority publishes the policy and mapping snapshot the Sidecar enforces.

| Field                                  | Type     | Default                                                                                        | Description                                                                                                                                                           |
| -------------------------------------- | -------- | ---------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `connect_addr`                         | address  | none                                                                                           | Advanced physical TCP destination; `url` remains the logical HTTP and TLS origin                                                                                      |
| `connect_timeout`                      | duration | `"10s"`                                                                                        | Connection timeout for the tonic channel                                                                                                                              |
| `reconnect_min_backoff`                | duration | `"250ms"`                                                                                      | Minimum reconnect backoff                                                                                                                                             |
| `reconnect_max_backoff`                | duration | `"30s"`                                                                                        | Maximum reconnect backoff                                                                                                                                             |
| `revocation_readiness_grace`           | duration | `"500ms"`                                                                                      | How long a connection may deliver no set before the sidecar warns; readiness still waits for an applied set                                                           |
| `revocation_fail_closed_on_disconnect` | bool     | `false`                                                                                        | Flip revocation readiness back to false when the stream drops                                                                                                         |
| `public_key_path`                      | path     | `<state_dir>/authority.pub` when present, else none                                            | Authority Ed25519 public key used to verify capabilities. Unset with no file present keeps the reject-all verifier.                                                   |
| `ca_cert_paths`                        | [path]   | `[<state_dir>/tls/authority-ca.crt]` when present and the Authority is on this host, else `[]` | PEM CA certificates. When any CA is named, the Authority's certificate must be signed by one of them and the platform's roots are ignored                             |
| `disable_platform_roots`               | bool     | `false`                                                                                        | Never verify the Authority against the platform's trusted roots. Already the behavior whenever `ca_cert_paths` names a CA; its only effect is rejecting an empty list |
| `credentials`                          | section  | none                                                                                           | Optional Sidecar PSK credentials sent on every Authority RPC.                                                                                                         |

Validation:

- `connect_timeout`, `reconnect_min_backoff`, and `reconnect_max_backoff` must
  all be greater than zero.
- `connect_addr` requires `url` and must use a nonzero port. For plaintext
  URLs, the insecure-remote check uses this physical address when present.
- `reconnect_max_backoff` must be ≥ `reconnect_min_backoff`.
- Every `ca_cert_paths` entry must be non-empty.
- `disable_platform_roots = true` requires a `ca_cert_paths` entry: the
  Sidecar would otherwise trust nothing.
- An `https://` `url` on this host requires a CA, named or adopted from the
  state directory.
- When `credentials` is present, `workspace_id` and `sidecar_id`
  must be non-empty, and exactly one PSK source must be configured.

#### `[sidecar.authority.credentials]`

Use this section when connecting a Sidecar to an Authority that requires a
pre-shared key. The PSK is issued by the Authority operator. It is resolved once
at startup, kept in memory, and sent on `IssueCapability`,
`WatchPolicyBundle`, and `WatchRevocations`.

```toml
[sidecar.authority.credentials]
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

A Sidecar that `firma run --agent` starts for one Firma Team run uses
that run's runtime credential instead of a pre-shared key:

```toml
[sidecar.authority.credentials]
workspace_id = "wsp_01j0000000e008000000000001"
sidecar_id = "sc_01j0000000e008000000000001"
run_id = "run_01j0000000e008000000000001"
runtime_credential_env = "FIRMA_RUNTIME_CREDENTIAL"
```

`runtime_credential_env` names the variable the Sidecar reads its runtime
credential from at startup; never list it in `env_passthrough`. The Sidecar
sends the value as the bearer of every Authority and Audit call together with
`firma-agent-flow-version: 1`, never sends the `credentials` body field, and
shuts down when the `firma run` that started it, declared in `FIRMA_RUN_PID`,
is gone. `run_id` is required with it, and it is exclusive with the
pre-shared key sources. It must be a canonical `run_` RunId; malformed
identifiers and legacy `ses_` managed identifiers are rejected during
configuration validation. Managed requests keep their session equal to this
run identifier; standalone session generation is unchanged.

Runtime credentials cannot use the legacy `grpc` audit sink: use `wal` for
durable delivery. For runtime credentials, the resolved WAL filename appends
`.<run_id>` to `wal_path` (for example, `audit.jsonl.run_...`), with its
lock and scope files beside it. Each run owns its journal. Earlier
runs' journals are retained, never automatically deleted or replayed
under a new run's bearer. Existing unqualified runtime journals are
left untouched. PSK configurations keep their configured paths and scope
format unchanged.

Behavior notes:

- Requests are denied with `POLICY_BUNDLE_NOT_READY` until the first
  bundle has been applied and `REVOCATION_CACHE_NOT_READY` until the
  first revocation set has been applied. `revocation_readiness_grace`
  never grants readiness: a Sidecar whose stream never delivers a set
  stays not-ready, however long it waits, and only warns once the grace
  elapses.
- The policy bundle TTL carried in each `PolicyBundleUpdate` is authoritative.
  When the deadline elapses without a refresh, Stage 2 denies with
  `PolicyBundleStale`.
- `revocation_fail_closed_on_disconnect = true` is the opt-in strict
  mode: a revocation stream drop flips readiness off and the sidecar
  denies all traffic with `REVOCATION_CACHE_NOT_READY` until the
  stream recovers.

### `[sidecar.revocation]`

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

### `[sidecar.audit]`

Audit event emitter settings. Controls where enforcement events are written and
how they are signed.

| Field                 | Type      | Default               | Description                                       |
| --------------------- | --------- | --------------------- | ------------------------------------------------- |
| `sink`                | string    | `stdout`              | `stdout`, `file`, `grpc`, `wal`                   |
| `file_path`           | path      | `<state>/audit.jsonl` | Append-only file path, used by the `file` sink    |
| `grpc_url`            | string    | none                  | Audit service URL (required for `grpc` and `wal`) |
| `buffer_path`         | path      | none                  | Local buffer file (required for `grpc` sink)      |
| `buffer_max_size`     | byte size | `"100 MiB"`           | Maximum local buffer size                         |
| `replay_ack_timeout`  | duration  | `"30s"`               | Wait for the collector to acknowledge a replay    |
| `wal_path`            | path      | none                  | Durable journal file (required for `wal`)         |
| `wal_max_size`        | byte size | `"100 MiB"`           | Maximum pending journal size                      |
| `wal_request_timeout` | duration  | `"5s"`                | Bound on each `wal` delivery attempt              |
| `signing_key_path`    | path      | `<state>/audit.key`   | ECDSA private key file path                       |
| `signing_key_env`     | string    | none                  | Env var containing ECDSA private key (PEM)        |

The `grpc` sink buffers outages. While the stream to `grpc_url` is unavailable it
appends events to `buffer_path` and replays them in order on reconnect. The
buffer is bounded by `buffer_max_size`; once full, the oldest events are
evicted rather than blocking the agent.

Buffered events are cleared only after the audit service acknowledges them, so
a replay that fails partway leaves them on disk for the next attempt. Events
survive a Sidecar restart: a new process picks up whatever its predecessor left
in `buffer_path`.

An unreachable audit service never blocks startup or the enforcement path. The
Sidecar starts in buffering mode, retries on an exponential backoff between
250 ms and 30 s, and bounds each connect attempt at 10 s. A replay waits up to
`replay_ack_timeout` for the collector's acknowledgment and keeps the buffer if
none arrives. New events queue behind the replay until then, so a larger value
lengthens the back-pressure on the agent when a collector stalls. Keep it above
the time the collector needs to persist a full `buffer_max_size` replay: a
replay that times out is resent whole on every reconnect, and new events keep
filling the buffer until the oldest are evicted. A collector that
stays connected but stops reading is treated like a disconnected one: events
go to the buffer instead of waiting for stream capacity. Events already handed
to that stream were never acknowledged and are lost with it; the Sidecar
counts them and reports the total when it stops, separately from the events
the buffer cap evicted.

A buffer that cannot be written — a full or read-only filesystem, for
instance — is not a degraded mode. With the stream down there is nowhere else
for an event to go, so the Sidecar logs the failure and shuts down rather than
keep enforcing calls whose evidence is discarded. Give `buffer_path` a
filesystem sized for `buffer_max_size`.

Relative paths in `buffer_path` and `wal_path` resolve against the configuration file's
directory, as they do for `file_path` and `signing_key_path`.

The buffer holds the same events the `file` sink writes, which name resources,
agents, and tokens. Its parent directory is created if missing, and on Unix the
directory is created with mode `0700` and the buffer file with mode `0600`.

Validation:

- `file_path` must be non-empty when set. Unset with the `file` sink resolves
  to `audit.jsonl` in the state directory.
- `grpc_url` must be set and non-empty when sink is `grpc` or `wal`, and must parse as
  an `http://` or `https://` URI with a host. The sink buffers and retries
  instead of dialing at startup, so an unusable URL is rejected here rather
  than looking like a collector outage at runtime.
- `buffer_path` must be set and non-empty when sink is `grpc`.
- `buffer_max_size` must be greater than zero.
- `wal_path` must be set and non-empty when sink is `wal`.
- `wal_max_size` must be greater than zero.
- `signing_key_path` and `signing_key_env` are mutually exclusive. With
  neither set, the key is read from `audit.key` in the state directory.

Both network sinks verify an `https://` `grpc_url` over TLS. When it names the
same origin as `[sidecar.authority].url` (scheme; host compared
case-insensitively, IP literals in canonical form; port), the audit service is trusted as the Authority is: its configured CAs
alone when any, otherwise the platform's trusted roots, with the Authority's
mTLS client identity. Any other host is verified against the platform's trusted
roots and gets no client identity; there is no separate audit CA setting, so a
collector with a private CA needs that CA in the bundle `SSL_CERT_FILE` names.
The configured Authority credentials go only to the Authority's origin as well,
over `http://` too: another host never receives what would let it call the
Authority as this Sidecar, and startup logs that the audit service is not the
Authority's. A host with no usable trusted roots stops startup.

The `wal` sink is separate from the buffered `grpc` sink. It syncs each event
before sending and reclaims it only after a matching durable per-event receipt.
Capacity exhaustion fails the sink instead of evicting pending records.
`wal_request_timeout` bounds each delivery attempt, from connecting through the
collector's durable commit. Set it above the collector's commit latency: an
attempt that times out is retried a second later, so a collector slower than the
bound receives the same record repeatedly while the journal fills. A replay pass
delivers up to 32 records, one attempt at a time, and new events wait for the
whole pass. Shutdown waits for the attempt in progress, so keep the value well
below your supervisor's termination grace period: events not yet journaled are
lost if the process is killed first. Both
network sinks attach configured Authority credentials, but `grpc` uses legacy
streaming and rejects run evidence. Live gRPC sends are not journaled and can be
lost on a broken stream; they do not provide the WAL's durable delivery contract.
Do not share a file between the two modes. See the
[audit guide](../docs-site/src/content/docs/guides/audit-log.md) for scope files,
rejection archives and recovery limits.

### `[sidecar.local_exec]`

Optional local-exec governance endpoint. When present, the sidecar binds an
additional Unix domain socket that `firma-run` clients contact for pre-execution
governance decisions on local tool invocations. If the section is absent, the
endpoint is not started.

This is the server-side counterpart to the `sidecar_local_exec` section in the
`firma-run` profile config.

| Field            | Type     | Default   | Description                                                                             |
| ---------------- | -------- | --------- | --------------------------------------------------------------------------------------- |
| `socket_path`    | path     |           | **Required.** Absolute path to the Unix domain socket file.                             |
| `default_action` | string   | `deny`    | Policy for fresh requests: `allow`, `deny`, or `pending_hitl` (HITL approval required). |
| `token_ttl`      | duration | `"5m"`    | Approval token lifetime. Must be > 0.                                                   |
| `retry_after`    | duration | `"500ms"` | Suggested retry interval returned to `firma-run` in `pending_hitl` responses. ≥ 1 ms.   |

Validation:

- `socket_path` must be an absolute path.
- `token_ttl` must be greater than zero; `retry_after` must be at least 1 ms
  because the local-exec wire protocol represents it in whole milliseconds.

Example:

```toml
[sidecar.local_exec]
socket_path = "/run/firma/local-exec.sock"
default_action = "pending_hitl"
token_ttl = "5m"
retry_after = "500ms"
```

The `pending_hitl` action triggers the HITL approval token flow: `firma-run`
receives a `pending_hitl` response with a single-use, short-lived `approval_token`;
for `async_token` mode, `firma-run` retries internally with the token until
`allow|deny` or timeout. See the Local-Exec Governance section in
`docs/architecture/command-governance-local-exec-contract.md` for the full protocol.

## Mapping Rules File

The files selected by `[authority].mapping_rules_paths` define how raw HTTP
requests are classified into canonical action classes.

```toml
[[rules]]
method = "POST"
host = "api.openai.com"
path = "/v1/chat/completions"
action_class = "communication.external.send"

[[rules]]
method = "GET"
host = "*.example.com"
action_class = "communication.external.read"
```

| Field          | Type   | Required | Description                              |
| -------------- | ------ | -------- | ---------------------------------------- |
| `method`       | string | no       | HTTP method to match; omit for any       |
| `host`         | string | yes      | Host pattern; `*` wildcard supported     |
| `path`         | string | no       | Path pattern; `*` wildcard supported     |
| `action_class` | string | yes      | Canonical action class from the registry |

Validation:

- A file may hold no rules; unmatched traffic is denied either way.
- `host` must not be empty, and `action_class` must name a canonical action
  class from the registry.
- `method`, when set, must be a valid HTTP method: `GET`, `POST`, `PUT`,
  `DELETE`, `PATCH`, `HEAD`, `OPTIONS`, or `CONNECT`.
- The same `(method, host, path)` matcher must not appear twice across the
  selected files.
