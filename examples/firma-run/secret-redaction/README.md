# Secret interception & HTTP redaction

Keep real secret values out of the agent while still letting sanctioned tools
use them. The agent only ever sees placeholders (`firma-secret://…`); the real
values live in the `firma run` broker, out of the sandbox.

Full design: [`docs/architecture/fir-429-pai-credential-injection.md`](../../../docs/architecture/fir-429-pai-credential-injection.md).

## Files

- `firma.toml` — run profile. `shims` lists the executables to interpose on;
  `[authority]` tells `firma run` to auto-start a per-process Authority +
  Sidecar that loads the Cedar policies below.
- `mapping-rules.toml` — Sidecar mapping rules. Maps the capture server
  endpoint to the `communication.external.send` action class so the Sidecar
  knows which Cedar policy to apply.
- `policies/secret-mediation.cedar` — Cedar policy with two permits:
  `secret.mediate` for the broker intercept path (bws), and
  `communication.external.send` for the Sidecar HTTP redact path.
- `scripts/mock-vault` — stand-in for the Bitwarden Secrets Manager CLI.
  Outputs a JSON array of `{ key, value }` objects; the broker intercepts its
  stdout, extracts each value via the built-in bitwarden JSONPath matcher, and
  replaces it with a `firma-secret://bitwarden/<name>` placeholder. `run.sh`
  exposes it as `bws` on PATH so the broker matches the built-in bitwarden
  integration spec.
- `scripts/capture-server` — HTTP server running outside the sandbox on
  `localhost:19876`. Receives rehydrated POST /capture requests and logs what it
  received so `run.sh` can verify the real secret arrived.
- `scripts/agent.py` — simulated agent that runs inside the sandbox. It calls
  `bws` (step 1: intercept) and then POSTs to the capture server via the Sidecar
  proxy (step 2: HTTP redact), asserting it only ever handles placeholder tokens.
- `run.sh` — orchestrates the demo end-to-end.

## The flow

1. **Fetch (broker intercept).** The agent calls `bws`. The `firma-secret-shim`
   routes the invocation through the out-of-sandbox broker, which runs the real
   `bws`, extracts secret values via the built-in bitwarden matcher, stores each
   value in the run-scoped secret store under a
   `firma-secret://bitwarden/<name>` placeholder, and returns output with every
   value replaced. The agent never sees a real secret.

2. **Use (Sidecar HTTP redact).** The agent POSTs `{"token": "<placeholder>"}` to
   `http://127.0.0.1:19876/capture` via the Sidecar HTTP proxy. The proxy bridge
   injects the session identity header and forwards the request to the Sidecar.
   The Sidecar resolves the placeholder to the real value via the gateway socket
   and rewrites the request body before forwarding to the capture server. The
   capture server receives (and logs) the real value. The Sidecar then scans the
   response for the real value and masks it back to the placeholder before the
   agent reads the response body.

Ordering matters: a placeholder only rehydrates if it is already in the
broker's secret store, so the agent must call `bws` (step 1) before it can use
the placeholder in an HTTP call (step 2).

## Running it

```sh
cargo build -p firma --release
examples/firma-run/secret-redaction/run.sh
```

`run.sh` starts the capture server, then calls `firma run` which auto-starts an
Authority + Sidecar loaded with the Cedar policy. After the demo, it verifies
that the capture server log contains the real secret value (proving the Sidecar
resolved the placeholder before forwarding).

## Invariants

- **Fail closed.** A broker error, gateway timeout, or unresolvable placeholder
  leaves the raw placeholder in the forwarded body, so the upstream server never
  receives a secret it is not supposed to receive.
- **Dictionary out-of-sandbox.** The placeholder ↔ secret map lives in the
  broker process; the in-sandbox shim and agent hold no real values.
- **Masking is best-effort.** A secret transformed before output (base64, hex,
  chunked) will not be masked; the primary control is that the agent only ever
  holds placeholders.
- **No extra config for rehydration.** Any ALLOWED outbound HTTP request body is
  scanned for `firma-secret://` placeholders; no per-request configuration is
  needed beyond a permit Cedar policy.
