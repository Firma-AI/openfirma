---
title: Run the sidecar standalone
description: Start a local Sidecar against a hand-written config and route an agent through it without firma run.
---

This guide walks you through running the Sidecar as a standalone process, pointing an agent at it, and observing decisions in the audit log. It is the next step after the [Quickstart](../../quickstart/) — you'll write your own config from scratch instead of using `make demo`.

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

Cedar requires a schema. Copy the demo's schema (it declares all the action classes) into the same directory:

```bash
cp $(pwd)/../../path/to/openfirma/examples/demo/policies/schema.cedarschema \
   /tmp/firma-standalone/config/policies/
```

(Adjust the path to your openfirma checkout. The schema is at `examples/demo/policies/schema.cedarschema`.)

## Step 5: Write the sidecar config

Create `/tmp/firma-standalone/config/firma.toml`. Every subcommand reads
one shared, sectioned `firma.toml`; the Sidecar reads `[sidecar.*]`:

```toml
[sidecar.interceptor]
mode               = "http_proxy"
listen_addr        = "127.0.0.1:8080"
drain_timeout_secs = 5

[sidecar.mapping]
rules_path        = "/tmp/firma-standalone/config/mapping-rules.toml"
default_protected = false

[sidecar.policy]
dir = "/tmp/firma-standalone/config/policies"

[sidecar.constraint_enforcement]
bundle_ttl_seconds     = 3600
enforcement_timeout_ms = 50

[sidecar.audit]
sink             = "file"
file_path        = "/tmp/firma-standalone/logs/audit.jsonl"
signing_key_path = "/tmp/firma-standalone/audit.key"

[sidecar.log]
level = "info"
```

A few notes on what's *not* here:

- No `[sidecar.authority].url`. With no Authority configured, the Sidecar runs in **policy-only** mode — Stage 1 (capability validation) is effectively bypassed for unmapped/protected actions. We use `default_protected = false` so unmapped traffic passes through, and we will only see Stage 2 decisions for the mapped routes. This is fine for first-touch experimentation; production workloads should run with an Authority and `default_protected = true`.
- No `[sidecar.ca]` section. We're not using HTTPS MITM. CONNECT-style HTTPS will pass through but we won't see L7 details for it. See [Enable HTTPS MITM](../https-mitm/) when you're ready.
- If you later set `authority.url = "http://..."`, note that plain HTTP is only accepted by default for loopback Authority hosts (`localhost`/`127.0.0.1`/`::1`). Non-loopback plaintext requires explicit opt-in with `authority.allow_insecure_remote_authority = true`.
- `bundle_ttl_seconds = 3600` is generous; without an Authority pushing fresh bundles, you don't want the bundle to go stale.

## Step 6: Start the Sidecar

```bash
firma sidecar -c /tmp/firma-standalone/config/firma.toml
```

Expected output (lightly trimmed):

```text
INFO firma_sidecar::startup: loading mapping rules
INFO firma_sidecar::startup: loaded 2 mapping rules
INFO firma_sidecar::startup: loading policy bundle from /tmp/.../policies
INFO firma_sidecar::startup: bundle compiled (1 file, 2 policies)
INFO firma_sidecar::interceptor::http: listening on 127.0.0.1:8080
INFO firma_sidecar::audit: file sink ready /tmp/.../logs/audit.jsonl
INFO firma_sidecar: sidecar ready
```

The `sidecar ready` line is your signal that the Sidecar accepted the config and is enforcing.

When `authority.url` is set, `ready` is held back until both the
policy-bundle and revocation streams have hydrated — so the line also means
policy is in place and the first request through the proxy can't race ahead of
it. With no Authority configured, the streams are pre-seeded ready and the line
fires immediately.

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

- `decision.outcome`: `"ALLOW"` or `"DENY"`.
- `envelope.intent.action_class`: `"communication.external.send"` for both.
- `envelope.intent.resource.host` / `.path` for the call destination.
- `decision.matched_policies`: which Cedar rules fired.
- A signature block (`signature`) that you can verify with the public side of `audit.key`.

For verifying the signature, see [Read & verify the audit log](../audit-log/).

## Common gotchas

**HTTPS calls show up as method `CONNECT`.** Without MITM, the only thing the Sidecar sees about HTTPS is the CONNECT line. The path is `/` and the action class will be whatever your rule maps `CONNECT host:443` to — probably nothing. To enforce on the inner HTTP details, set up MITM ([guide](../https-mitm/)).

**`PolicyBundleStale` denies after ~an hour.** Without an Authority, the bundle is loaded once at startup and never refreshed; once `bundle_ttl_seconds` elapses, every Stage 2 evaluation denies. Either bump the TTL very high for development, or run a local Authority that pushes refreshes.

**`MappingNotFound` for unfamiliar destinations.** With `default_protected = true`, anything you didn't map denies. That's the right shape in production; for development, leave `default_protected = false` until you've enumerated the rules you actually want.

**Permission denied on `audit.key`.** The Sidecar reads it at startup; `chmod 600` is fine. If the key is unreadable, startup fails fast and prints the path it tried.

## What's next

This setup gives you a Sidecar that audits and enforces against destinations you map, using a hand-written Cedar policy. From here:

- [Inspect live sidecars with `firma sidecar status`](../firma-sidecar-status/) — list and probe per-run sidecars started by `firma run`, with JSON output and stale-marker GC.
- [Start and monitor the daemon with `firma sidecar` and `firma monitor`](../manage-the-stack/) — supervise Authority + Sidecar as one unit and live-tail decisions, instead of running each binary by hand.
- [Write your first Cedar policy](../write-a-cedar-policy/) — go beyond the two-rule demo and learn the policy patterns.
- [Issue capability tokens](../issue-capability-tokens/) — add an Authority and a real Stage 1 layer.
- [Enable HTTPS MITM](../https-mitm/) — see L7 details for HTTPS hosts.
- [Read & verify the audit log](../audit-log/) — turn the JSONL into a tamper-evident record.
