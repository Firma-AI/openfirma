---
title: Issue capability tokens
description: Configure automatic per-session capability issuance and refresh with firma run.
---

A capability token is what an agent needs to clear
[Stage 1](../../concepts/pipeline/) of the enforcement pipeline. `firma run`
requests a signed capability from the Authority before launching an agent,
loads it into the per-run Sidecar, and refreshes it during long sessions.

By the end of this guide you will have:

- an Authority signing key and issuance policy;
- a registered agent identity;
- automatic per-session capability issuance and refresh; and
- a Sidecar that verifies each capability before using it at Stage 1.

## Step 1: Scaffold the project

Start from a generated project configuration:

```bash
firma config --profile generic --posture dev --mapping anthropic
```

The scaffold creates the Authority signing key, runtime and issuance policy
directories, revocation file, and the shared sectioned `firma.toml`. Protect
the private key: anyone who can read it can mint capabilities your Sidecars
will accept.

The generated `[authority]` section includes the capability lifetime limits:

```toml
[authority]
max_ttl = "1h"
bundle_ttl = "30s"
```

- `max_ttl` limits the lifetime of every issued capability.
- `bundle_ttl` is the freshness deadline advertised in streamed policy
  bundles. Protected requests fail closed with `PolicyBundleStale` if that
  deadline passes before a refresh arrives.

Both values must be positive, whole-second durations within their supported
ranges. You can override them for one Authority process with the same duration
syntax:

```bash
FIRMA_AUTHORITY_MAX_TTL=30m \
FIRMA_AUTHORITY_BUNDLE_TTL=15s \
firma authority --config .firma/firma.toml
```

Environment values take precedence over `firma.toml`. Malformed, negative,
zero, fractional-second, and out-of-range values fail Authority startup.

## Step 2: Define the issuance policy

The Authority evaluates a separate Cedar bundle before it issues a
capability. This bundle answers whether an agent may receive the requested
actions and resource scope; the runtime policy independently decides whether
each concrete outbound call is allowed.

For local development, the generated issuance policy permits all requests. A
more selective policy can name registered agents and remove sensitive actions:

```cedar
permit (
    principal in [
        Firma::Agent::"agt_01j0000000e008000000000001",
        Firma::Agent::"agt_01j0000000e008000000000002"
    ],
    action,
    resource
);

forbid (
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
    action == Firma::Action::"payment.transfer",
    resource
);
```

Validate policy changes before starting the Authority:

```bash
firma policy validate --file .firma/issuance-policies/issuance.cedar
```

The Authority also validates policies at startup and hot reload. An invalid
edit is rejected, and the Authority continues streaming the last valid
runtime bundle.

## Step 3: Configure the agent identity and trust root

`firma run` uses `[sidecar.authority].agent_id` in every
`IssueCapabilityRequest`. The value is an `agt_` TypeID assigned to the agent:

```toml
[sidecar.authority]
agent_id = "agt_01j0000000e008000000000001"
public_key_path = "/path/to/authority.pub"
```

`agent_id` is independent of the local run profile. `[run].profile` selects
runtime behavior, while the registered TypeID identifies the principal to the
Authority.

The public key file must contain the raw 32-byte Ed25519 public key matching
the Authority's signing key. `firma run` verifies the returned PASETO before
it starts the agent and writes the same effective key into the autostarted
Sidecar configuration.

## Step 4: Run the agent

Start the wrapped process:

```bash
firma run --profile generic -- curl https://example.com
```

Before launch, `firma run`:

1. resolves the Authority and registered agent identity;
2. creates a new session identity;
3. requests the allowed action set and resource scope over gRPC;
4. verifies the signed PASETO response locally; and
5. makes the verified capability available to the per-run Sidecar.

The Sidecar indexes the capability by `(session_id, action_class, resource)`.
Stage 1 denies requests when no matching capability exists, the signature is
invalid, the token is expired or revoked, or its scope does not match.

Authority denials such as `AGENT_NOT_REGISTERED` and
`AGENT_PROFILE_MISMATCH` stop the run before the agent starts and preserve the
Authority's diagnostic message.

## Automatic refresh

Capabilities are short-lived. `firma run` refreshes a capability before it
expires, using the same session identity and Authority credentials. The
Sidecar watches the per-run capability file and atomically installs each
verified replacement without restarting.

```toml
[run.profiles.generic.capability]
refresh_ratio = 0.60
grace = "30s"
```

- `refresh_ratio` selects how far through the remaining lifetime renewal is
  scheduled.
- `grace` ensures renewal starts no later than the configured time before
  expiry.

Refresh remains fail closed. If the Authority is unavailable, retries use
backoff but the expired token is never served. If a replacement fails
verification, the Sidecar keeps the current valid capability until it expires.
Every refresh re-evaluates the issuance policy and revocation state.

## Revocation

Revoke a capability by its canonical `ctok_` TypeID:

```bash
firma authority --config .firma/firma.toml \
  revocations add ctok_01j0000000e008000000000001
```

The Authority records the token ID and broadcasts a revocation event.
Connected Sidecars update their local revocation stores, so subsequent use of
the capability is denied without a hot-path Authority call.

Compact expired revocations periodically:

```bash
firma authority --config .firma/firma.toml revocations compact
```

## Common errors

**`TokenInvalid`.** Check that the requested action and resource are covered,
the run and capability have the same session identity, and the configured
Authority public key matches the signing key.

**`TokenExpired`.** Check Authority reachability and refresh logs. The
refresher never extends or serves an expired token.

**Authority refuses to issue.** The issuance policy denied the request, or the
registered agent identity does not match the requested profile. Check the
Authority diagnostic and adjust the registration or policy deliberately.

**`PolicyBundleStale`.** The Sidecar did not receive a bundle refresh before
`bundle_ttl` elapsed. Check the Authority connection and health.

## What's next

- [Wrap an agent with `firma run`](../firma-run/) — configure sandbox and
  runtime behavior.
- [Write your first Cedar policy](../write-a-cedar-policy/) — define runtime
  decisions for capability-authorized calls.
- [Capabilities](../../concepts/capabilities/) — understand validation,
  refresh, and revocation.
