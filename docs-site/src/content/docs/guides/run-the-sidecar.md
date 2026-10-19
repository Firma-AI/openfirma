---
title: Run the sidecar standalone
description: Start a local Sidecar against a hand-written config and route an agent through it without firma run.
---

This guide walks you through running the Sidecar as a standalone process, pointing an agent at it, and observing decisions in the audit log. It is the next step after the [Quickstart](../../quickstart/) — you'll write your own config from scratch instead of using `just demo`.

By the end you will have:

- A working `firma.toml` you understand line by line.
- A running Sidecar that audits every outbound call to the configured destinations.
- A simple agent (just `curl`) routed through it, demonstrating fail-closed denials without a capability.

This guide does **not** provision capabilities or cover [`firma run`](../firma-run/) (the sandbox wrapper) or HTTPS MITM. To reach the Cedar ALLOW/DENY decisions, first provision a session capability using [Issue capability tokens](../issue-capability-tokens/).

## Prerequisites

- A built workspace: `cargo build --release` from the repo root.
- `protoc` installed.
- `openssl` for generating the audit signing key.
- `curl` for the test calls.

The release binary lives at `target/release/firma`. If you'd rather use cargo run, substitute `cargo run --release -p firma -- <args>` for `firma <args>` below.

## Step 1: Create a workspace directory

Pick a directory for the Sidecar's runtime files:

```bash
mkdir -p /tmp/firma-standalone/{config,logs}
cd /tmp/firma-standalone
```

This keeps all the dev artifacts in one place so you can blow it away cleanly later.

## Step 2: Generate the audit signing key

The Sidecar signs every audit event with an ECDSA P-256 key. Generate one:

```bash
openssl genpkey \
  -algorithm EC \
  -pkeyopt ec_paramgen_curve:P-256 \
  -out /tmp/firma-standalone/audit.key
```

Keep this file private. It's your tamper-evidence root.

## Step 3: Write the mapping rules

Create `/tmp/firma-standalone/config/mapping-rules.toml`:

```toml
# Map legitimate calls. Unmatched destinations are denied.

[[rules]]
method       = "GET"
host         = "wttr.in"
path         = "*"
action_class = "communication.external.send"

[[rules]]
method       = "POST"
host         = "paste.rs"
path         = "*"
action_class = "communication.external.send"
```

These rules classify weather queries and paste requests. Both remain denied until a valid capability authorizes the request's session, action, and resource.

## Step 4: Write a minimal Cedar policy

Create `/tmp/firma-standalone/config/policies/`:

```bash
mkdir -p /tmp/firma-standalone/config/policies
```

Create `/tmp/firma-standalone/config/policies/default.cedar`:

```cedar
// Permit weather lookups; forbid pastes. A minimal demonstration policy.

permit (
    principal,
    action == Firma::Action::"communication.external.send",
    resource
) when {
    context.risk_score < 80
};

forbid (
    principal,
    action == Firma::Action::"communication.external.send",
    resource == Firma::Resource::"paste.rs/"
);
```

The Sidecar evaluates Cedar policies streamed from a running Authority — not
from `[sidecar.policy].dir` alone. That directory is hashed for startup logs;
runtime enforcement comes from the Authority bundle stream. Offline validation
uses the embedded schema via [`firma policy validate`](../test-policies-offline/).

## Step 5: Generate Authority material and write `firma.toml`

Generate the Authority signing key and a permissive issuance policy for this
dev stack:

```bash
firma authority generate-key -o /tmp/firma-standalone/authority.key
mkdir -p /tmp/firma-standalone/config/issuance
cat > /tmp/firma-standalone/config/issuance/issuance.cedar <<'EOF'
permit (principal, action, resource);
EOF
touch /tmp/firma-standalone/revocations.txt
```

Create `/tmp/firma-standalone/config/firma.toml`. Every subcommand reads one
shared, sectioned `firma.toml`:

```toml
[authority]
mapping_rules_paths = ["/tmp/firma-standalone/config/mapping-rules.toml"]
listen_addr         = "[::1]:50051"
policy_dir          = "/tmp/firma-standalone/config/policies"
issuance_policy_dir = "/tmp/firma-standalone/config/issuance"
revocation_file     = "/tmp/firma-standalone/revocations.txt"
key_file            = "/tmp/firma-standalone/authority.key"
max_ttl = "1h"
bundle_ttl = "30s"

[sidecar.interceptor]
mode               = "http_proxy"
listen_addr        = "127.0.0.1:8080"
drain_timeout = "5s"

[sidecar.policy]
dir = "/tmp/firma-standalone/config/policies"

[sidecar.authority]
url             = "http://[::1]:50051"
public_key_path = "/tmp/firma-standalone/authority.pub"

[sidecar.audit]
sink             = "file"
file_path        = "/tmp/firma-standalone/logs/audit.jsonl"
signing_key_path = "/tmp/firma-standalone/audit.key"
```

Notes:

- **`[sidecar.authority].url` is required.** The Sidecar refuses to start
  without it and reports ready only after the Authority publishes its policy
  and mapping snapshot.
- The standalone Sidecar does not request capabilities. Use `firma run` for
  automatic per-session issuance before sending protected requests; see
  [Issue capability tokens](../issue-capability-tokens/).
- Mappings are loaded by the Authority; unmatched destinations are always denied.
- No `[sidecar.ca]` section — these demo curls use plain HTTP. See
  [Enable HTTPS MITM](../https-mitm/) when you need L7 visibility on TLS.
- Duration values keep their compact unit-bearing syntax, such as `"5s"`.
  Timeout, deadline, wait, retry, and session-lifetime controls reject zero
  during config parsing. TTL, grace, and clock-skew values retain their
  field-specific semantics; for example, a zero clock-skew tolerance means
  strict expiry checking.

## Step 6: Start the Authority, then the Sidecar

Two terminals.

**Terminal 1 — Authority:**

```bash
firma authority --no-tls -c /tmp/firma-standalone/config/firma.toml
```

`--no-tls` explicitly selects plaintext for this loopback-only development stack,
matching the Sidecar's `http://` Authority URL. Without it, Authority startup
requires TLS material.

**Terminal 2 — Sidecar:**

```bash
firma sidecar -c /tmp/firma-standalone/config/firma.toml
```

Wait for `sidecar ready`. This line is held until the Authority policy and
revocation streams hydrate — so the first proxied request cannot race ahead of
enforcement.

## Step 7: Send traffic through it

In another terminal, route a couple of curl calls through the proxy:

```bash
# DENY (HTTP 403): no session capability is provisioned in this guide.
curl --proxy http://127.0.0.1:8080 http://wttr.in/london?format=3

# DENY (HTTP 403) for the same missing-capability reason.
curl --proxy http://127.0.0.1:8080 -X POST http://paste.rs/ -d 'leaked'
```

Both calls return 403 at Stage 1, before Cedar evaluation or upstream dispatch.
These denials do not prove the Cedar forbid policy ran. Once a matching
capability is provisioned and its session is attached to each request, the
weather call can reach the permit policy and the paste call reaches the forbid
policy.

## Step 8: Read the audit log

```bash
tail -n 2 /tmp/firma-standalone/logs/audit.jsonl
```

You'll see two records (one per curl), each with:

- `decision`: `2` for DENY.
- `action`: `"raw.http.GET"` or `"raw.http.POST"` for these early capability denials.
- `resource`: `"wttr.in/london?format=3"` or `"paste.rs/"` for these requests.
- `deny_reason`: `"token invalid: no capability token covers action ..."`, naming
  the mapped action class and resource.
- `signature`: a base64-encoded DER signature that you can verify with the public side of `audit.key`.

For verifying the signature, see [Read & verify the audit log](../audit-log/).

## Common gotchas

**HTTPS calls show up as method `CONNECT`.** Without MITM, the only thing the Sidecar sees about HTTPS is the CONNECT line. The path is `/` and the action class will be whatever your rule maps `CONNECT host:443` to — probably nothing. To enforce on the inner HTTP details, set up MITM ([guide](../https-mitm/)).

**`policy bundle stale` or readiness denies.** These appear when the Sidecar
cannot use a fresh Authority-backed policy bundle or revocation view. You do
not need to sequence the Authority before the Sidecar by hand:
the Sidecar retries Authority streams with backoff, stays fail-closed, and
emits `sidecar ready` only after the required streams hydrate. For
deployment probe guidance, see
[startup ordering and readiness](../deploy-a-genai-webapp/#step-6-configure-startup-ordering-and-readiness).

**`UnclassifiedIntent` for unfamiliar destinations.** Add an explicit Authority
mapping for each legitimate destination. There is no Sidecar passthrough setting
for unmatched traffic; see [Extend the mapping](../extend-mapping/).

**Permission denied on `audit.key`.** The Sidecar reads it at startup; `chmod 600` is fine. If the key is unreadable, startup fails fast and prints the path it tried.

## What's next

This setup gives you a Sidecar that audits and enforces against destinations you map, using a hand-written Cedar policy. From here:

- [Inspect live sidecars with `firma sidecar status`](../firma-sidecar-status/) — check per-run sidecar health with table or JSON output.
- [Start and monitor the daemon with `firma sidecar` and `firma monitor`](../manage-the-stack/) — supervise Authority + Sidecar as one unit and live-tail decisions, instead of running each binary by hand.
- [Write your first Cedar policy](../write-a-cedar-policy/) — go beyond the two-rule demo and learn the policy patterns.
- [Issue capability tokens](../issue-capability-tokens/) — configure automatic Stage 1 issuance.
- [Enable HTTPS MITM](../https-mitm/) — see L7 details for HTTPS hosts.
- [Read & verify the audit log](../audit-log/) — turn the JSONL into a tamper-evident record.
