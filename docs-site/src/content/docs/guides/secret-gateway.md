---
title: Rehydrate & mask secrets with the secret gateway
description: Configure placeholder-based secret handling — outbound rehydration, inbound masking, and HTTP vault interception — for the Sidecar.
---

New to secret handling? Start with [Secrets without handing them to
agents](../../concepts/secrets/) for the problem, workflow, and a built-in
example. This guide covers detailed configuration and operational behavior.

`firma run` manages the gateway and broker for its per-run Sidecar automatically
via `secret_providers` in `firma.toml`. This is the only turnkey lifecycle
OpenFirma currently ships. See [External gateway endpoints](#external-gateway-endpoints)
before connecting a standalone Sidecar to another implementation.

The gateway guide assumes the placeholder workflow from the concept page. For
the exact built-in behavior, matcher schema, scoping, and masking boundaries,
use the [secret provider reference](../secret-provider-reference/).

## Fail-closed guarantees

This feature follows the same fail-closed invariant as the rest of
enforcement — no partial or best-effort forwarding:

- **Enabled rehydration is all-or-nothing.** When a gateway client is
  configured, if any detected placeholder in a request body cannot be resolved,
  the Sidecar denies the whole request
  (`FailClosed`) rather than forward a body with some placeholders
  substituted and others left as literal, unresolvable tokens.
- **A blocked HTTP vault command never dispatches.** A vault command
  matched as `blocked` in the provider's matcher config is rejected
  *before* the connector is contacted — not dispatched and then discarded —
  so a destructive vault call (delete, overwrite) never reaches the
  upstream vault in the first place.
- **A failed push aborts the response.** HTTP vault interception
  substitutes a freshly minted placeholder into the response body as it
  extracts each secret. If pushing that secret to the gateway then fails,
  the Sidecar aborts the whole response (`CREDENTIAL_INJECTION_FAILED`)
  instead of handing the agent a placeholder the gateway never learned —
  a token that could never resolve.

## Step 1: Configure `secret_providers` via `firma run` (recommended)

Add `secret_providers` under `[run.defaults]` or a single
`[run.profiles.<id>]`. Each entry is either a bare string naming a built-in
CLI integration — [1Password](https://developer.1password.com/docs/cli/)
(`"op"`),
[Bitwarden Secrets Manager](https://bitwarden.com/help/secrets-manager-cli/)
(`"bws"`),
[HashiCorp Vault](https://developer.hashicorp.com/vault/docs/commands)
(`"vault"`), or [Doppler](https://docs.doppler.com/docs/cli) (`"doppler"`) — or
a full table defining a custom CLI or HTTP provider. Entries from defaults and
the active profile are merged; a later entry wins on name collision (profile
overrides defaults, custom overrides built-in). Bare-string HTTP providers are
not supported — define them as a full `{ type = "http", ... }` table.

### Provider forms

- **CLI entry** — activates an in-sandbox shim for that binary. The shim
  forwards the real vault CLI through the `firma-run` broker, which classifies
  the invocation (`sensitive_command` / `safe_command` / `blocked_command`),
  rewrites output options, extracts secrets via its `matcher`, and stores them
  under opaque `fsp_…` placeholders the gateway resolves later. An entry being
  present is itself the authorization to intercept — no separate policy check
  gates it.
- **CLI providers must be noninteractive.** The broker gives the provider a
  null stdin, so prompts, piped input, and `-` stdin arguments are unsupported.
  It buffers the provider's complete stdout and stderr before the shim replays
  either stream. If either stream exceeds the broker capture limit, the whole
  invocation is rejected without returning partial output.
- **VZ readiness does not run a provider.** The broker exposes a versioned
  readiness operation for guest bundles after the host bridge is installed;
  incompatible control versions fail closed instead of dispatching a CLI.
- **VZ keeps secret custody on the host.** In isolated VZ mode, the guest gets
  an integrity-checked shim with a musl or no dynamic ELF interpreter and the
  canonical `FIRMA_SECRET_BROKER_ADDR` pointing to a loopback endpoint backed
  by VSOCK. The plaintext store, gateway, and host broker socket remain in the
  owner-only host control directory. Explicit launch metadata contains the
  provider names, shim share directory, host broker socket, guest broker
  address, and target needed by the runner, but excludes capability tokens,
  broker environment values, and other internal shim metadata from the guest
  command environment. If the target-qualified shim is missing, unreadable,
  non-executable, built for the wrong architecture or C runtime, or differs
  from the guest manifest checksum, launch fails with the path, target, and
  reinstall remedy.
- **CLI mediation requires backend shim support.** It is active on the Linux
  bwrap backend through a host bind mount and on the macOS VZ guest backend
  through the isolated VSOCK broker bridge. WSL2 and macOS sandbox-exec
  compatibility mode are unsupported because the wrapped process can call the
  host directly, so a shim would be redundant. Firecracker support is planned
  but not yet implemented.
- **Install the private shim with the repository-owned installer.** Run the
  documented `curl | sh` installer to receive the target-qualified shim. On
  macOS, it downloads and checksum-verifies the matching Linux-musl shim
  archive. Running
  `brew install Firma-AI/openfirma/firma` directly currently installs only the
  CLI because the external tap does not package this private resource; VZ CLI
  mediation then fails closed during preflight. The shim is intentionally not
  exposed on `PATH`.

  A custom VZ guest bundle records the exact required shim digest in
  `manifest.txt`; install that matching shim rather than mixing artifacts from
  another build. Published releases through `v0.1.6` predate the private
  artifact, so installing one of them, whether selected with `--version` or as
  the latest release, installs only the CLI; a missing shim in a current or
  newer release aborts before changing the installation. The installer keeps
  the shim under `libexec/openfirma/secret-shims/<linux-musl-target>/` beside
  `firma`.
- **HTTP entry** — mirrored into the autostarted Sidecar's
  `[sidecar].http_secret_providers` so the Sidecar can intercept matching vault
  responses at L7. HTTPS requires MITM for the provider host; plaintext HTTP and
  already-decoded gRPC/Unix-socket requests do not. Fail-closed: an unknown
  vault path is `blocked`, and extraction or gateway-push failure aborts the
  response.

```toml
[run.defaults]
secret_providers = [
  "bws",  # built-in Bitwarden Secrets Manager CLI

  # custom CLI vault — full spec
  { type = "cli", binary_name = "mock-vault", provider_id = "mock-vault", credential_env_vars = [], matchers = [
    { type = "sensitive_command", argv = ["secret", "list"], matcher = { type = "json", record_path = "$[*]", value_path = "$.value", name = { source = "path", path = "$.key" } } },
    { type = "safe_command", argv = ["secret", "status"] },
    { type = "blocked_command", argv = ["secret", "delete"] },
  ] },

  # custom HTTP vault — mirrored to the Sidecar
  { type = "http", provider_id = "aws-secrets-manager", host = "secretsmanager.*.amazonaws.com", matchers = [
    { type = "sensitive_command", path = "/GetSecretValue", matcher = { type = "json", record_path = "$", value_path = "$.SecretString", name = { source = "path", path = "$.Name" } } },
    { type = "safe_command", path = "/health" },
  ] },
]
```

Run normally — `firma run` spawns the gateway, wires
`FIRMA_SECRET_GATEWAY_ADDR` for the Sidecar, and writes the mirrored
`http_secret_providers` into the per-run Sidecar config:

```bash
firma run --profile generic -- your-agent
```

For complete local examples using full custom specs rather than built-ins, see
[`examples/custom-cli-secret`](https://github.com/Firma-AI/openfirma/tree/main/examples/custom-cli-secret)
and
[`examples/custom-http-secret`](https://github.com/Firma-AI/openfirma/tree/main/examples/custom-http-secret).
Both use deterministic mock applications and verify that the sandboxed client
receives placeholders instead of plaintext.

See the [secret provider reference](../secret-provider-reference/) for built-in
command support, every custom provider field, JSON/regex matchers, domain
scoping, environment isolation, limits, encodings, and failure timing.

Validate the resolved set without launching:

```bash
firma run --profile generic --print-effective-config -- echo hi | jq .secret_providers
```

## Step 2: Configure HTTP vault interception

The recommended `firma run` configuration is the full HTTP table shown above.
If you operate a Sidecar with a compatible external gateway, the equivalent
direct entry is `[[sidecar.http_secret_providers]]`:

```toml
[[sidecar.http_secret_providers]]
provider_id = "internal-vault"
host        = "vault.internal.example.com"

[[sidecar.http_secret_providers.matchers]]
type = "sensitive_command"
path = "/v1/secret/data/*"

[sidecar.http_secret_providers.matchers.matcher]
type        = "json"
record_path = "$"
value_path  = "$.data.value"

[sidecar.http_secret_providers.matchers.matcher.name]
source = "path"
path   = "$.data.name"

[[sidecar.http_secret_providers.matchers]]
type = "safe_command"
path = "/v1/health"

[[sidecar.http_secret_providers.matchers]]
type = "blocked_command"
path = "/v1/secret/metadata/*"
```

Each matcher entry resolves in a fixed order — `blocked_command` first, then
`sensitive_command`, then `safe_command` — so list them by how strict a path
needs to be, not the order you expect requests to arrive in. A path that
matches none of them is treated as blocked by default: interception fails
closed on an unrecognized shape rather than forward it unredacted.

Matchers are compiled once when the Sidecar starts, not per request. An
invalid `matcher` — a regex without the required named capture groups, or a
bad JSONPath — prevents the Sidecar from starting rather than silently
skipping or degrading interception. Fix the matcher and restart the Sidecar.

- **`sensitive_command`** — extract secrets from the response body using
  `matcher`, mint a placeholder for each, and substitute it into the body
  before it reaches the agent.
- **`safe_command`** — forward the response unmodified; the shape is known
  to never carry secret material (e.g. a health check).
- **`blocked_command`** — reject the call before it ever reaches the vault.
  Use this for destructive operations (delete, overwrite) your policy
  should never allow through this path, independent of Cedar policy.

For an HTTPS vault, provider configuration alone does not enable MITM. Add a
separate host pattern to the inherited Sidecar template:

```toml
[sidecar.interceptor.https_mitm]
enabled = true
intercept_hosts = ["*.amazonaws.com"]
strict_hosts = ["*.amazonaws.com"]

[run.defaults]
secret_providers = [
  { type = "http", provider_id = "aws-secrets-manager", host = "secretsmanager.*.amazonaws.com", matchers = [
    { type = "sensitive_command", path = "/GetSecretValue", matcher = { type = "json", record_path = "$", value_path = "$.SecretString", name = { source = "path", path = "$.Name" } } },
  ] },
]
```

The patterns intentionally differ. Provider host globs allow `*` anywhere and
across DNS labels. MITM accepts exact hosts or a leading suffix wildcard that
matches one or more preceding labels; it does not accept
`secretsmanager.*.amazonaws.com`. Use `strict_hosts` when a failed TLS
interception must deny rather than fall back to CONNECT-only.

Plain HTTP and already-decoded gRPC/Unix-socket requests are already visible at
L7 and do not require TLS interception.

### External gateway endpoints

OpenFirma does not ship a public standalone gateway/broker command or a stable
third-party gateway protocol. `firma run` is the supported turnkey option. A
standalone Sidecar can be pointed at a compatible implementation with
`FIRMA_SECRET_GATEWAY_ADDR`, but that peer becomes part of the plaintext secret
custody boundary and protocol compatibility may change between releases.

Accepted client addresses are:

- `tcp://<loopback-ip>:<port>` on any platform. Non-loopback addresses are
  rejected and the transport relies on loopback isolation.
- `unix:///absolute/path` on Unix. The existing path must be a real socket, not
  a symlink, with mode `0600`; its immediate parent must be a directory with
  mode `0700`.

Neither transport authenticates the external gateway process, UID, or socket
owner. Unix type and mode checks are filesystem hardening only. Control and
verify the complete socket path and gateway process before trusting the peer.

Any present endpoint with invalid syntax, transport, or Unix-socket metadata
fails Sidecar startup. An absent address is allowed only when no HTTP providers
are configured. A syntactically valid but unreachable or incompatible peer does
not prevent startup; each resolution or push attempts a new connection and
fails that request or response closed. Client tuning defaults to one second for
connection, one second per operation, and a 10 MB inbound response-line cap:

```toml
[sidecar.secret_gateway]
connection_timeout = "1s"
operation_timeout  = "1s"
max_buffer_size    = "10MB"
```

The Sidecar client does not apply `max_buffer_size` to its outbound request.
The managed in-tree gateway independently defaults its incoming request-line
cap to 10 MB. Changing the Sidecar client setting does not configure an external
gateway server.

For `firma run`, `run.profiles.<id>.secret_gateway_addr` takes precedence over
the `FIRMA_SECRET_GATEWAY_ADDR` environment fallback during profile resolution.
If any `secret_providers` are active, however, `firma run` starts its own
per-run services and replaces either value with the managed gateway address.

## Step 3: Verify

With MITM enabled for the vault host and the gateway reachable, a request
that echoes a matched secret comes back to the agent with the value already
replaced by a placeholder:

```json
{ "data": { "name": "db-password", "value": "fsp_01hz8k7g3v9m2q4x6r1n0p5t8w" } }
```

If a downstream call later needs that same secret, send the placeholder
token in the request body; the Sidecar rehydrates it immediately before
dispatch, so the agent does not need to possess the value. Response masking then
applies only to values rehydrated for that request and only at or above the
eight-byte floor. It does not mask every value known to the run-wide gateway.

Use a `domain_selector` whenever vault output identifies the intended service.
A scoped placeholder resolves only for an exact matching authority. Every
explicit port remains significant, including `:80` and `:443`; a scoped
authority with a port does not match one that omits it. A domain mismatch denies
the entire request. Without a selector, the placeholder is unscoped and can
resolve for any request host; the vault host is not inferred as its destination.
See [Domain-scoped
rehydration](../secret-provider-reference/#domain-scoped-rehydration).

## Common gotchas

**Request denied with `FailClosed` and no other explanation.** The body
contained a placeholder the gateway couldn't resolve — check that the
gateway is reachable and that the placeholder was actually pushed (e.g. by
an earlier interception) before this request.

**Response aborted with `CREDENTIAL_INJECTION_FAILED`.** The Sidecar
could not safely mediate a sensitive vault response. This includes a response
that does not match the configured schema, invalid selector cardinality/domain,
unsupported or corrupt compression, exceeding the decompressed-body limit,
recompression failure, or a failed gateway push. Check the provider response,
matcher, `sidecar.interceptor.max_decompressed_body_size`, gateway connectivity,
and `[sidecar.secret_gateway]` timeouts.

**A vault path returns denied even though it's read-only.** Every path not
explicitly listed as `sensitive_command` or `safe_command` is treated as
`blocked_command`. Add the path to the provider's matcher list.

**The Sidecar fails to start with an invalid secret-provider diagnostic.**
Matchers are compiled at startup, and one invalid matcher (a regex without
named capture groups or a bad JSONPath) rejects the whole configuration.
Fix the matcher and restart the Sidecar.

**`FIRMA_SECRET_GATEWAY_ADDR` unset.** If `http_secret_providers` is
configured, the Sidecar fails to start because it cannot safely intercept
vault responses without a gateway. Without HTTP providers, gateway-backed
rehydration and masking remain disabled until the variable is set; request
bodies are not scanned and literal `fsp_…` tokens pass through unchanged.

**A short secret is visible in an echoed response.** Inbound masking skips
values shorter than eight bytes by design. Use longer credentials or ensure the
upstream never echoes the short value.

**A placeholder remains literal in Composio traffic.** The dedicated Composio
handler currently bypasses placeholder rehydration, response masking, and HTTP
provider interception. Do not rely on the secret gateway for Composio requests.

## What's next

- [Inject credentials](../inject-credentials/) — the static, host-scoped
  alternative to placeholder-based secret mediation.
- [Enable HTTPS MITM](../https-mitm/) — required to inspect encrypted HTTP vault
  response bodies.
- [Concepts: Interception](../../concepts/interception/) — how the Sidecar
  gets traffic into the pipeline in the first place.
