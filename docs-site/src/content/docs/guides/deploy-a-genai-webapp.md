---
title: Deploy a GenAI web app
description: Put a multi-user web app that calls LLMs behind OpenFirma — capability per user session, policy per tenant, audit per request.
---

A GenAI web app — a customer support assistant, an internal copilot, an "AI feature" inside a SaaS — is a different shape from a local coding agent. It serves many users at once, each session has different scope, and the security boundary needs to enforce per-tenant rules without becoming a bottleneck.

This guide shows how to put such an app behind OpenFirma. It builds on every other guide; cross-links are inline. The example app: a multi-tenant assistant where each user has their own session and the app calls OpenAI and a vendor SaaS on their behalf.

## Architecture

```text
┌──────────────────┐                ┌─────────────────────────┐
│  HTTPS clients   │──── HTTPS ────►│   Web app (Node/Py/Go)  │
└──────────────────┘                │   issues per-session    │
                                    │   capabilities, makes   │
                                    │   outbound LLM calls    │
                                    └────────┬────────────────┘
                                             │ HTTP_PROXY=...
                                             ▼
                                    ┌─────────────────────────┐
                                    │      Sidecar            │ ◄── per-pod or per-host
                                    │  (enforcement + inject) │
                                    └────────┬────────────────┘
                                             │
                                             ├──► api.openai.com (allowed)
                                             ├──► api.acme-vendor.com (allowed)
                                             └──X paste.rs (denied)

                                    ┌─────────────────────────┐
                                    │     Authority           │ ◄── shared by all Sidecars
                                    │  (issuance + bundles)   │
                                    └─────────────────────────┘
```

Three deployment shapes for the Sidecar:

- **Per-pod sidecar** (Kubernetes / containers). Standard sidecar pattern: each app pod has a Sidecar container, the app talks to it over loopback. Right for production — strong tenant isolation, easy to scale horizontally.
- **Per-host daemon** (VM / bare metal). One Sidecar per host, all app processes on the host route through it. Right for simpler topologies.
- **Embedded** (gRPC interceptor mode). Sidecar in-process with the app via the gRPC interceptor. Right when you control the app's HTTP client and want zero proxy footprint.

The rest of this guide uses **per-pod sidecar**. The patterns translate to the other shapes with minor config changes.

## Step 1: Define the agent identity model

In a multi-tenant web app, "the agent" is not the app. The agent is the **session** — what the app is doing on behalf of one user. The choice that matters most:

| Choice                        | Meaning                                      | Use when                            |
| ----------------------------- | -------------------------------------------- | ----------------------------------- |
| One registered ID per tenant  | Sessions are sub-units of a tenant agent.    | Per-tenant policies, shared models. |
| One registered ID per user    | Each end user has a distinct agent identity. | Strict per-user audit isolation.    |
| One registered ID for the app | The whole app shares one agent identity.     | Single-tenant; minimal isolation.   |

This guide stores one Authority-issued `agt_` TypeID for each tenant and uses
`session_id = <user-session-uuid>`. Do not construct an agent ID from the tenant
name: keep a tenant-to-agent-ID mapping returned by registration. That gives you
per-tenant policies plus per-session isolation in the audit log.

## Step 2: Set up shared infrastructure

**One Authority** for the whole deployment. It signs every capability your app mints, streams policy bundles, broadcasts revocations.

```toml
# /etc/firma/firma.toml — the [authority] section
[authority]
listen_addr         = "0.0.0.0:50051"   # or behind an internal load balancer
policy_dir          = "/etc/firma/policies"
issuance_policy_dir = "/etc/firma/issuance"
revocation_file     = "/var/lib/firma/revocations.txt"
key_file            = "/etc/firma/firma-authority.key"
max_ttl = "1h"              # capabilities live at most 1h
bundle_ttl_seconds  = 30                # Sidecars deny if a bundle is not refreshed before this TTL
```

In production, run the Authority on a hardened host with limited access. Treat its signing key with the same care as a CA key.

The CA for HTTPS MITM (if you're using it) lives separately on each Sidecar host — see [Enable HTTPS MITM](../https-mitm/). Each host has its own CA; you don't share one across hosts.

## Step 3: Write the issuance policy

This is the policy that decides whether the app can ever mint a capability. It runs once per session, so it can afford richer checks.

`/etc/firma/issuance/issuance.cedar`:

```cedar
// Tenant-scoped agents may request these classes.
permit (
    principal,
    action == Firma::Action::"communication.external.send",
    resource
) when {
    // Authority-issued agent IDs for tenants we recognize
    principal == Firma::Agent::"agt_01j0000000e008000000000001" ||
    principal == Firma::Agent::"agt_01j0000000e008000000000002" ||
    principal == Firma::Agent::"agt_01j0000000e008000000000003"
};

// No tenant gets payment classes from this app.
forbid (
    principal,
    action == Firma::Action::"payment.transfer",
    resource
);
```

The tenant list itself is declarative. When you onboard a new tenant, you add a line and push the bundle — no code change. When you offboard one, you remove the line and revoke their active capabilities.

## Step 4: Write the runtime policy

`/etc/firma/policies/genai-app.cedar`:

```cedar
// LLM calls: permitted to OpenAI for known tenants.
permit (
    principal,
    action == Firma::Action::"communication.external.send",
    resource
) when {
    resource == Firma::Resource::"api.openai.com/v1/chat/completions"
};

// Vendor SaaS: permitted to one specific endpoint, with rate limits
// enforced via context.action_count.
permit (
    principal,
    action == Firma::Action::"communication.external.send",
    resource
) when {
    resource == Firma::Resource::"api.acme-vendor.com/api/v1/assistant" &&
    context.action_count <= 100
};

// Hard floor: no exfiltration destinations, ever.
forbid (
    principal,
    action == Firma::Action::"communication.external.send",
    resource
) when {
    resource == Firma::Resource::"paste.rs/" ||
    resource == Firma::Resource::"transfer.sh/" ||
    resource == Firma::Resource::"0x0.st/"
};
```

`context.action_count` is the per-session call counter. The rule "max 100 vendor calls per session" caps a runaway loop.

## Step 5: Configure the Sidecar

Each app pod runs a Sidecar with this config:

```toml
# /etc/firma/firma.toml — the [sidecar.*] sections
[sidecar.interceptor]
mode               = "http_proxy"
listen_addr        = "127.0.0.1:8080"
drain_timeout = "30s"

[sidecar.interceptor.https_mitm]
enabled         = true
intercept_hosts = ["api.openai.com", "api.acme-vendor.com"]
strict_hosts    = ["api.acme-vendor.com"]    # never fall back to CONNECT here

[sidecar.ca]
dir = "/etc/firma/firma-ca"

[sidecar.mapping]
rules_path  = "/etc/firma/mapping-rules.toml"
rules_paths = []
default_protected = true                      # production!

[sidecar.policy]
dir           = "/etc/firma/cache/policies"   # populated by Authority stream

[sidecar.capability_seed]
paths = []                                   # capabilities arrive via gRPC, not seed files

[sidecar.authority]
url             = "https://firma-authority.internal:50051"
public_key_path = "/etc/firma/firma-authority.pub"
ca_cert_path    = "/etc/firma/authority-ca.crt"

[sidecar.connector]
default_timeout_ms = 30000

[[sidecar.connector.hosts]]
host       = "api.openai.com"
rps        = 100
burst      = 20
timeout_ms = 30000

[[sidecar.connector.hosts]]
host       = "api.acme-vendor.com"
rps        = 50
burst      = 10
timeout_ms = 15000

[sidecar.credentials.openai]
target_host    = "api.openai.com"
mode           = "vault"
header         = "Authorization"
prefix         = "Bearer "
secret_path    = "/run/secrets/openai-api-key"

[sidecar.credentials.acme_vendor]
target_host    = "api.acme-vendor.com"
mode           = "vault"
header         = "x-api-key"
secret_path    = "/run/secrets/acme-vendor-api-key"

[sidecar.audit]
sink             = "grpc"
grpc_url         = "https://audit-collector.internal:9090"
signing_key_path = "/etc/firma/audit.key"

```

A few things worth highlighting:

- **`default_protected = true`** — anything not in mapping rules denies. Production posture.
- **`[sidecar.authority].url` uses `https://` + `[sidecar.authority].ca_cert_path`** — sidecar verifies Authority identity before trusting streamed bundles/revocations.
- **`reconnect_min_backoff` / `reconnect_max_backoff`** — Sidecars retry Authority streams with bounded exponential backoff. The defaults are `"250ms"` and `"30s"`.
- **`grpc` audit sink** — events go to a centralized collector, not to a local file. Multiple Sidecars feed one collector.
- **Vault Agent for credentials** — no API keys in the app. Vault Agent renders short-lived files and the Sidecar reads them per call.
- **`strict_hosts` on the vendor** — if MITM fails (e.g. cert mismatch), the call denies rather than falling back to weaker CONNECT-only policy.

## Step 6: Configure startup ordering and readiness

You can start the Authority and Sidecar at the same time. Do not add a
shell loop that waits for the Authority before launching the Sidecar. The
Sidecar connects to the Authority with independent `WatchPolicyBundle`
and `WatchRevocations` streams. If either stream is unavailable, it keeps
retrying with exponential backoff and stays fail-closed.

The request path is blocked until both Authority-backed stores are ready:

- The policy bundle stream has delivered and applied its first bundle.
- The revocation stream has either delivered its first event or the
  `revocation_readiness_grace_ms` window has elapsed.

Only after both gates pass does the Sidecar emit `sidecar ready`. Before
that point, protected traffic denies locally with readiness errors such as
`POLICY_BUNDLE_NOT_READY` or `REVOCATION_CACHE_NOT_READY`; it is not sent
upstream.

Configure the backoff in `[sidecar.authority]` only when your platform
needs different timing:

```toml
[sidecar.authority]
url                           = "https://firma-authority.internal:50051"
public_key_path               = "/etc/firma/firma-authority.pub"
ca_cert_path                  = "/etc/firma/authority-ca.crt"
reconnect_min_backoff         = "250ms"
reconnect_max_backoff         = "30s"
revocation_readiness_grace_ms = 500
```

For Cloud Run multi-container services, make the Sidecar's health endpoint
the probe that gates traffic. Use `GET /healthz` on port `9000`, the
default `--health-bind-addr` port, for both startup and readiness. Cloud
Run's
[container health checks](https://docs.cloud.google.com/run/docs/configuring/healthchecks)
distinguish startup, readiness, and liveness; the important rule is that
startup success must also mean the container is safe to receive traffic.
Pointing startup and readiness at the Sidecar ready gate satisfies that
rule and avoids a separate sequencing script.

```yaml
containers:
  - name: app
    image: us-docker.pkg.dev/example/app:latest
    env:
      - name: HTTPS_PROXY
        value: http://127.0.0.1:8080

  - name: firma-sidecar
    image: us-docker.pkg.dev/example/firma-sidecar:latest
    ports:
      - name: health
        containerPort: 9000
    startupProbe:
      httpGet:
        path: /healthz
        port: 9000
      periodSeconds: 1
      failureThreshold: 60
    readinessProbe:
      httpGet:
        path: /healthz
        port: 9000
      periodSeconds: 2
      failureThreshold: 3
```

Use the same endpoint for a Kubernetes `readinessProbe` if you run the
same container pair there. Keep liveness separate: a liveness failure
should mean the Sidecar process is wedged and should be restarted, not
that the Authority is briefly unreachable during startup.

## Step 7: Per-session capability issuance

The app's request handler issues a fresh capability for each user session. Pseudocode (Python):

```python
import grpc
from firma_proto import authority_pb2, authority_pb2_grpc

def issue_capability_for_session(tenant_id: str, user_session_id: str):
    channel = grpc.secure_channel(
        "firma-authority.internal:50051",
        grpc.ssl_channel_credentials(...),
    )
    stub = authority_pb2_grpc.AuthorityStub(channel)
    req = authority_pb2.IssuanceRequest(
        agent_id=tenant_agent_ids[tenant_id],
        session_id=user_session_id,
        requested_actions=[
            "communication.external.send",
        ],
        resource_scope="*",
        requested_ttl_seconds=900,    # 15 minutes
    )
    resp = stub.IssueCapability(req)
    if resp.HasField("denied"):
        raise PermissionError(resp.denied.reason)
    return resp.allowed.raw_token
```

When a user starts a session, the app calls `issue_capability_for_session(...)`, hands the resulting raw token to the Sidecar via the appropriate channel (a header on the proxied request, or a side channel — your design), and from then on the Sidecar can validate every call from that session against that capability.

For a 15-minute TTL with 1000 active sessions, the Authority issues 1000 capabilities every 15 minutes. The Sidecar holds them in its `CapabilityMap`. The hot path is unchanged.

## Step 8: Wire the app to the proxy

Set the app's HTTP client to use the loopback Sidecar:

**Python (httpx / requests):**

```bash
HTTP_PROXY=http://127.0.0.1:8080 \
HTTPS_PROXY=http://127.0.0.1:8080 \
SSL_CERT_FILE=/etc/firma/firma-ca/firma-ca.crt \
python -m gunicorn app:app
```

**Node:**

```bash
HTTPS_PROXY=http://127.0.0.1:8080 \
NODE_EXTRA_CA_CERTS=/etc/firma/firma-ca/firma-ca.crt \
node app.js
```

The app does *not* read `OPENAI_API_KEY` or vendor secrets. They live in Vault, the Sidecar pulls them, the app just makes calls without auth headers.

## Step 9: Multi-tenancy in the audit log

Every request the app proxies produces an audit event tagged with the tenant's
registered `agt_` agent ID and `session_id = <user-session>`. Ship those events
to your collector keyed on `agent_id` and you have **per-tenant audit by
construction** — no app-side instrumentation needed.

For per-user accounting on top of that, the `session_id` is the unit. If you record the mapping `(session_id → user_id)` somewhere, you can join the audit stream against it.

## Step 10: Operational concerns

A few practices that come up only at production scale.

**Authority HA.** The Authority is a single point of contact for capability issuance. Run two of them behind a load balancer; both point at the same `policy_dir` and key file. The Sidecar's gRPC stream is independent per-Sidecar, and Sidecars reconnect automatically.

**Bundle propagation latency.** Policy updates travel over the Authority's gRPC stream. Monitor stream health and confirm that Sidecars received a new version before relying on tightened rules.

**Revocation propagation.** A `firma authority revocations add <token_id>` propagates within a second on the gRPC stream. For "kill this tenant immediately", run revocation against every active capability for that tenant.

**Capacity planning.** Each Sidecar holds active capabilities + the policy bundle in memory. With 1000 active sessions and a 100 KB bundle, you're well under 100 MB resident. The hot path stays bounded by the perf budgets (Stage 1 < 1ms, Stage 2 < 200µs) regardless of session count.

**Failure modes.** If the Authority is unreachable past its configured `bundle_ttl`, Sidecars deny protected requests with `PolicyBundleStale`. They also cannot receive policy or revocation updates, and capability issuance is unavailable. Monitor the Authority streams and Sidecar readiness accordingly.

## Tenant onboarding flow

Putting it all together, the new-tenant workflow is:

1. Register NewCo and store its Authority-issued `agt_` agent ID.
2. Add that ID to the issuance policy and any tenant-specific runtime rules.
3. Push the policy bundle and confirm that Sidecars received the streamed update.
4. Configure the app's tenant mapping to use NewCo's registered agent ID.
5. First session for the tenant: app calls `IssueCapability`, gets a token, app makes calls, Sidecar validates.

Offboarding is the inverse: remove the entries from issuance + runtime policy, push, the Sidecar denies new capabilities and stale ones expire.

## Common gotchas

**`PolicyBundleStale` denials in production.** The Sidecars did not receive a refresh before the Authority-advertised bundle TTL expired. Check the network path, the Authority's health, and the Sidecars' stream and readiness logs.

**`ScopeViolation` for legitimate calls.** The capability's `resource_scope` doesn't match the request. Either tighten the scope at issuance time or loosen it. Match the scope to the agent's mission, not to a wildcard — `'*'` is a smell in production.

**Audit volume.** A busy app produces a lot of events. Plan for the storage and the cost of shipping them. `grpc` sink + a horizontally scaled collector is the right shape.

**Vault token rotation.** AppRole renewal needs to happen before the token expires; the Sidecar does not auto-renew. Use a sidecar-of-the-sidecar (e.g. Vault Agent) to keep credentials fresh.

**Sidecar restart drops in-memory capabilities.** When a pod restarts, the Sidecar comes back with no `CapabilityMap` entries until sessions issue new ones. The app should retry on `TokenInvalid` by re-issuing.

## What's next

- [Read & verify the audit log](../audit-log/) — operational practice for the multi-tenant log stream.
- [Concepts: Threat model](../../concepts/threat-model/) — what this protects against and what it doesn't.
- [Concepts: Connectors](../../concepts/connectors/) — for the per-host rate-limit and credential-injection details.
