# Quick Start

You'll go from zero to a running sidecar that enforces your own Cedar policy
against a real agent in about 10 minutes.

## 1. Build the binaries

```bash
cargo build --release -p firma-sidecar -p firma-authority
```

Outputs: `target/release/firma-sidecar`, `target/release/firma-authority`.

## 2. Bootstrap keys

```bash
# Authority signing key — root of trust for all capability tokens
./target/release/firma-authority generate-key --output authority.key
```

## 3. Write your first policy

Create `policies/my-agent.cedar`:

```cedar
// Allow your agent to make external HTTP calls when risk is low.
permit (
    principal == Firma::Agent::"my-agent",
    action == Firma::Action::"communication.external.send",
    resource
) when {
    context.risk_score < 60
};

// Hard-block any call to a specific host, regardless of risk score.
// forbid always overrides permit.
forbid (
    principal == Firma::Agent::"my-agent",
    action == Firma::Action::"communication.external.send",
    resource == Firma::Resource::"api.example-blocked.com/"
);
```

The `action` values come from the [44-class registry](../reference/action-class-registry.md).
The sidecar maps every incoming request's `(method, host, path)` to one of
these classes before Stage 2 runs.

## 4. Configure the sidecar

Create `sidecar.toml`:

```toml
[interceptor]
mode        = "http_proxy"
listen_addr = "127.0.0.1:8080"

[interceptor.https_mitm]
enabled         = true
intercept_hosts = ["*"]   # MITM all HTTPS so the policy sees the full request

[policy]
dir           = "policies"
authority_url = "http://127.0.0.1:50051"

[ca]
dir = "./firma-ca"

[log]
level = "info"
```

## 5. Issue a capability for your agent

```bash
./target/release/firma-authority issue \
  --key authority.key \
  --agent-id my-agent \
  --session-id session-001 \
  --action "communication.external.send" \
  --output capability-my-agent.toml
```

The sidecar reads `capability-my-agent.toml` at startup and maps it to
`my-agent`'s session. Stage 1 validates the token; Stage 2 runs the Cedar
policy against it.

## 6. Start Authority and Sidecar

Terminal 1 — Authority:

```bash
./target/release/firma-authority \
  --key authority.key \
  --policy-dir policies \
  --listen "[::1]:50051"
```

Terminal 2 — Sidecar:

```bash
./target/release/firma-sidecar --config sidecar.toml
```

Wait for this log line before sending traffic:

```log
INFO firma_sidecar: ready
```

## 7. Wire your agent

Point any HTTP client or agent SDK at the sidecar proxy and trust the sidecar
CA cert for HTTPS:

```bash
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
export REQUESTS_CA_BUNDLE=./firma-ca/ca.crt   # Python
# export NODE_EXTRA_CA_CERTS=./firma-ca/ca.crt  # Node.js
```

Then run your agent normally. Every outbound call it makes routes through the
sidecar. No SDK changes needed — the proxy env vars are honored by virtually
every HTTP client library.

Quick test with curl:

```bash
# Should ALLOW (hits an allowed host, risk_score=0 < 60)
curl -x http://127.0.0.1:8080 --cacert ./firma-ca/ca.crt https://api.openai.com/

# Should DENY (blocked by the forbid rule above)
curl -x http://127.0.0.1:8080 --cacert ./firma-ca/ca.crt https://api.example-blocked.com/
```

## 8. Read the audit log

The sidecar emits a signed audit event for every decision. Check stdout or the
configured audit sink:

```log
decision=Allow  agent=my-agent  action_class="communication.external.send"  resource="api.openai.com/"
decision=Deny   agent=my-agent  action_class="communication.external.send"  resource="api.example-blocked.com/"  reason=PolicyDenied
```

Every event is signed with ECDSA P-256. See
[Audit Log Consumption](../operations/audit-logs.md) for the full schema and
verification procedure.

## What just happened

| Step             | What it does                                                                |
| ---------------- | --------------------------------------------------------------------------- |
| Write policy     | You own the Cedar rules — the sidecar enforces exactly what you wrote       |
| Issue capability | Authority mints a PASETO v4 token scoped to your agent + action             |
| Stage 1          | Sidecar validates the token locally (< 1 ms p95)                            |
| Stage 2          | Sidecar evaluates your Cedar policy (< 200 µs p95)                          |
| HTTPS MITM       | Sidecar decrypts HTTPS so the policy sees method + path, not just host:port |
| Audit            | Every ALLOW and DENY is signed and emitted, regardless of outcome           |

## Where next

- [Writing Cedar Policies](../guides/writing-policies.md) — conditions, forbid
  override semantics, composing multiple policy files
- [Capability Lifecycle](../guides/capability-lifecycle.md) — issuance,
  revocation, short TTLs
- [Integrating with Agents](../guides/integrating-agents.md) — SDK-specific
  guides for OpenAI Agents SDK, Google ADK, and others
- [firma-run Sandbox](../guides/firma-run.md) — structural confinement for
  agents that ignore `HTTP_PROXY`
- [Configuration](./configuration.md) — full sidecar config reference
