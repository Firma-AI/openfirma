# Quick Start

## What you'll do

Boot the Mini Authority, pre-issue a capability seed, boot the Sidecar, then
send one ALLOW request and one DENY request through the enforcement pipeline.
All steps run locally with no cloud dependencies.

## One-command demo

```bash
make demo-ci
```

Expected output:

```text
[allow] 200 OK path=/allow body={"ok":true,"path":"/allow"}
[deny] 403 Forbidden path=/deny body={"denied":true,"reason":"...","detail":"..."}
[ok] ALLOW + DENY round-trips matched expectation.
```

The demo boots Authority at `[::1]:50051` and Sidecar at `127.0.0.1:7474`.

Audit log highlights emitted by the Sidecar:

```text
decision=Allow  action_class="http.get"  resource="…/allow"
decision=Deny   action_class="http.post" resource="…/deny"
```

## Step-by-step (manual)

1. Build release binaries:

   ```bash
   cargo build --release -p firma-sidecar -p firma-authority
   ```

2. Generate an Authority signing key:

   ```bash
   ./target/release/firma-authority generate-key --output authority.key
   ```

3. Start the Authority (in a separate terminal):

   ```bash
   ./target/release/firma-authority --config examples/demo/authority.toml
   ```

4. Pre-issue a capability seed:

   ```bash
   ./target/release/firma-authority --config examples/demo/authority.toml issue \
     --agent-id demo-agent --session-id demo-session \
     --action communication.external.send \
     --output capability-demo-agent.toml
   ```

5. Start the Sidecar:

   ```bash
   ./target/release/firma-sidecar --config examples/demo/sidecar.toml
   ```

   Wait for the `ready` log line before sending traffic.

6. Send a request (should ALLOW):

   ```bash
   curl -x http://127.0.0.1:7474 http://127.0.0.1:9100/allow
   ```

## What just happened

Each step corresponds to a layer in the architecture:

- **Step 2** — The Authority signing key is the root of trust for all PASETO v4
  tokens. No external CA is involved.
- **Step 4** — The Authority issued a PASETO v4 capability token bound to
  `demo-agent` and `communication.external.send`. The token carries the agent
  identity, session, expiry, and Cedar policy claims.
- **Step 5** — The Sidecar loaded the capability seed from `sidecar.toml` and
  connected to the Authority over a long-lived gRPC stream to receive policy
  bundle updates and revocation events. No capability is fetched on the hot path.
- **Step 6** — The request flowed through the pipeline: the Interceptor captured
  it, the Normalizer classified it as `http.get`, Stage 1 selected and validated
  the token, Stage 2 evaluated the Cedar policy (allow), the Connector dispatched
  the call, and the Audit sink emitted a signed `ExecutionEvent`.

## Where next

- [Configuration](./configuration.md) — tuning interceptor mode, policy
  directories, HTTPS MITM, and mapping rules.
- [Writing Cedar Policies](../guides/writing-policies.md) — how to express
  fine-grained allow/deny rules.
- [Integrating with Agents](../guides/integrating-agents.md) — wiring
  `firma-sidecar` into an existing agent process.
