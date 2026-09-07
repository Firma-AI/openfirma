---
title: Rehydrate & mask secrets with the secret gateway
description: Configure placeholder-based secret handling — outbound rehydration, inbound masking, and HTTP vault interception — for the Sidecar.
---

`firma run` can manage the gateway for its per-run Sidecar automatically via
`secret_providers` in `firma.toml` (recommended). For a standalone Sidecar
(`firma sidecar start` / systemd) configure `[sidecar.http_secret_providers]`
/ `[sidecar.secret_gateway]` and `FIRMA_SECRET_GATEWAY_ADDR` manually — see
[Manual Sidecar configuration](#manual-sidecar-configuration) below.

The secret gateway lets the Sidecar exchange **placeholder tokens** for real
secret values without the agent ever holding the plaintext. It's a different
mechanism from [static credential injection](../inject-credentials/): where
injection attaches a fixed, host-scoped credential the Sidecar already knows
about, the gateway mediates secrets that live in an external vault and are
identified dynamically by placeholder, on both sides of a call:

- **Rehydration (outbound):** if a request body contains a `fsp_…`
  placeholder token, the Sidecar resolves it against the gateway and
  substitutes the real secret before dispatch.
- **Masking (inbound):** if a response body echoes a secret the Sidecar
  knows about, the Sidecar rewrites it back to its placeholder before the
  agent sees it. Matching is content-type aware: a secret re-echoed with
  JSON escaping, XML entities, or percent-encoding — including one embedded
  in a longer value such as an error message — is still recognized and
  masked.
- **HTTP vault interception:** if a response comes from a configured HTTP
  vault (e.g. a secrets-manager `GetSecret` call), the Sidecar extracts the
  secret directly from the response, mints a placeholder for it, pushes the
  real value to the gateway, and hands the agent only the placeholder.

The gateway itself — the process holding the actual secret dictionary — is
`firma-run`'s broker. The Sidecar never caches secrets across requests; it
queries the gateway per call.

## Fail-closed guarantees

This feature follows the same fail-closed invariant as the rest of
enforcement — no partial or best-effort forwarding:

- **Rehydration is all-or-nothing.** If any placeholder in a request body
  cannot be resolved, the Sidecar denies the whole request
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
CLI integration (e.g. `"bws"` for Bitwarden Secrets, `"op"` for 1Password) or a
full table defining a custom CLI or HTTP provider. Entries from defaults and
the active profile are merged; a later entry wins on name collision (profile
overrides defaults, custom overrides built-in). Bare-string HTTP providers are
not supported — define them as a full `{ type = "http", ... }` table.

- **CLI entry** — activates an in-sandbox shim for that binary. The shim
  forwards the real vault CLI through the `firma-run` broker, which classifies
  the invocation (`sensitive_command` / `safe_command` / `blocked_command`),
  rewrites output options, extracts secrets via its `matcher`, and stores them
  under opaque `fsp_…` placeholders the gateway resolves later. An entry being
  present is itself the authorization to intercept — no separate policy check
  gates it.

  CLI secret mediation is available on backends that declare shim support:
  the Linux bwrap backend (host bind-mount) and the macOS VZ guest backend
  (isolated guest with VSOCK broker bridge). WSL2 and sandbox-exec
  compatibility mode are unsupported because the wrapped process can call the
  host directly, so a shim would be redundant. Firecracker support is planned
  but not yet implemented.

  Install with the repository-owned `curl | sh` installer to receive the
  target-qualified private shim used by these backends. On macOS, that
  installer completes both its tarball and Homebrew branches by downloading
  and checksum-verifying the matching Linux-musl shim archive. Running
  `brew install Firma-AI/openfirma/firma` directly currently installs the CLI
  only because the external tap does not yet package this private resource;
  VZ CLI-provider mediation then fails closed during preflight. The shim is
  intentionally not exposed on `PATH`.
  A custom VZ guest bundle records the exact shim digest in `manifest.txt`;
  install that matching shim rather than mixing artifacts from another build.
  Published releases through `v0.1.6` predate this private artifact. When one
  of those versions is explicitly selected with `--version`, the installer
  reports that it is installing the historical CLI only; missing shims in
  current or newer release archives abort before the installation is changed.
  Tarball installs keep the shim under
  `libexec/openfirma/secret-shims/<linux-musl-target>/` beside `firma`.
  The Homebrew branch preinstalls it outside versioned kegs under
  `$(brew --prefix)/var/openfirma/secret-shims/<version>/<linux-musl-target>/`.
- **HTTP entry** — mirrored into the autostarted Sidecar's
  `[sidecar].http_secret_providers` so the Sidecar's MITM path can intercept
  matching vault responses. Fail-closed: an unknown vault path is `blocked`, a
  failed gateway push aborts the response.

```toml
[run.defaults]
secret_providers = [
  "bws",  # built-in Bitwarden Secrets CLI

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

Validate the resolved set without launching:

```bash
firma run --profile generic --print-effective-config -- echo hi | jq .secret_providers
```

## Step 2: Configure HTTP vault interception (optional, standalone Sidecar)

When not using `firma run`'s autostart, configure HTTP vault interception
directly on the Sidecar.

### Manual Sidecar configuration

Start the gateway and point the Sidecar at it. Run `firma-run`'s broker so
it's listening on a `unix://` or `tcp://` endpoint, then set that address in
the Sidecar's environment before it starts:

```bash
FIRMA_SECRET_GATEWAY_ADDR=unix:///run/firma/secret-shims/gateway.sock \
firma sidecar -c firma.toml
```

On Windows, use a `tcp://` endpoint instead (`tcp://127.0.0.1:51234`) since Unix
sockets aren't available.

Tune the gateway client's timeouts and buffer cap under
`[sidecar.secret_gateway]` — every field is optional and falls back to a
1-second timeout / 10 MB buffer cap:

```toml
[sidecar.secret_gateway]
connection_timeout = "1s"
operation_timeout  = "1s"
max_buffer_size    = "10MB"
```

### HTTP provider entries

If you want the Sidecar to extract secrets directly from a vault's HTTP
responses — rather than only rehydrating placeholders another component
already minted — add an entry per vault host under
`[[sidecar.http_secret_providers]]`:

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

Requires MITM for the vault host — see [Enable HTTPS
MITM](../https-mitm/) — since interception reads the decrypted response
body.

## Step 3: Verify

With MITM enabled for the vault host and the gateway reachable, a request
that echoes a matched secret comes back to the agent with the value already
replaced by a placeholder:

```json
{ "data": { "name": "db-password", "value": "fsp_01hz8k7g3v9m2q4x6r1n0p5t8w" } }
```

If a downstream call later needs that same secret, send the placeholder
token in the request body; the Sidecar rehydrates it before dispatch and the
real value never appears in the agent's process.

## Common gotchas

**Request denied with `FailClosed` and no other explanation.** The body
contained a placeholder the gateway couldn't resolve — check that the
gateway is reachable and that the placeholder was actually pushed (e.g. by
an earlier interception) before this request.

**Response aborted with `CREDENTIAL_INJECTION_FAILED`.** The Sidecar
extracted a secret from a vault response but couldn't push it to the
gateway. Check gateway connectivity and `[sidecar.secret_gateway]`
timeouts — a slow gateway under `operation_timeout` looks the same as one
that's down.

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
rehydration and masking remain disabled until the variable is set.

## What's next

- [Inject credentials](../inject-credentials/) — the static, host-scoped
  alternative to placeholder-based secret mediation.
- [Enable HTTPS MITM](../https-mitm/) — required for HTTP vault
  interception to see response bodies.
- [Concepts: Interception](../../concepts/interception/) — how the Sidecar
  gets traffic into the pipeline in the first place.
