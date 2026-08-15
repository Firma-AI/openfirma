---
title: Rehydrate & mask secrets with the secret gateway
description: Configure placeholder-based secret handling — outbound rehydration, inbound masking, and HTTP vault interception — for the Sidecar.
---

:::caution[Manual configuration only, for now]
This feature currently requires hand-writing `[sidecar.http_secret_providers]` /
`[sidecar.secret_gateway]` into the Sidecar's `firma.toml` and setting
`FIRMA_SECRET_GATEWAY_ADDR` in the Sidecar's process environment yourself.
`firma-run`'s autostart path does not yet synthesize these from its own
`secret_providers` config or spawn the gateway automatically — that wiring
has not landed. Treat everything below as the currently supported,
manually-configured path.
:::

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

## Step 1: Start the gateway and point the Sidecar at it

Run `firma-run`'s broker so it's listening on a `unix:` or `tcp:` endpoint,
then set that address in the Sidecar's environment before it starts:

```bash
FIRMA_SECRET_GATEWAY_ADDR=unix:/run/firma/secret-shims/gateway.sock \
firma sidecar -c firma.toml
```

On Windows, use a `tcp:` endpoint instead (`tcp:127.0.0.1:51234`) since Unix
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

## Step 2: Configure HTTP vault interception (optional)

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

**`FIRMA_SECRET_GATEWAY_ADDR` unset.** Rehydration, masking, and HTTP vault
interception are all silently disabled — this is intentional (nothing to
fail closed on if the feature isn't configured at all), not a bug.

## What's next

- [Inject credentials](../inject-credentials/) — the static, host-scoped
  alternative to placeholder-based secret mediation.
- [Enable HTTPS MITM](../https-mitm/) — required for HTTP vault
  interception to see response bodies.
- [Concepts: Interception](../../concepts/interception/) — how the Sidecar
  gets traffic into the pipeline in the first place.
