# HTTP-vault secret interception & redaction

The HTTP counterpart of [`../secret-redaction/`](../secret-redaction/): here
the "vault" is an HTTP service the agent calls directly, and interception
happens on the Sidecar's own HTTP path instead of a `firma run` broker shim
over stdio. The agent only ever sees placeholders (`firma-secret://…`); the
real values live in the `firma run` broker, out of the sandbox.

Full design: [`docs/architecture/fir-429-pai-credential-injection.md`](../../../docs/architecture/fir-429-pai-credential-injection.md).
See also the [HTTP vaults](../../../docs-site/src/content/docs/guides/redact-tool-secrets.md#http-vaults)
section of the secret-redaction guide.

## Files

- `firma.toml` — run profile. `secret_providers` has one `type = "http"`
  entry (`demo-http-vault`) instead of a CLI one — no shim, no
  `sidecar_local_exec` governance socket needed for the fetch itself. Listing
  the entry here is itself the authorization to intercept it, no Cedar policy
  required. `[authority]` tells `firma run` to auto-start a per-process
  Authority + Sidecar that loads the Cedar policy below.
- `mapping-rules.toml` — Sidecar mapping rules. Maps both the vault and the
  capture-server endpoints to the `communication.internal.send` action class
  so the Sidecar knows which Cedar policy to apply to each request.
- `policies/communication.cedar` — Cedar policy permitting
  `communication.internal.send` for both outbound calls (vault fetch,
  capture-server redact).
- `scripts/vault-server` — stand-in for a cloud secrets manager's HTTP API.
  Serves `GET /secret/<name>` with a JSON body shaped like a typical
  "get secret value" response (`{"Name": ..., "SecretString": ...}`). Has no
  knowledge of Firma — the Sidecar is what keeps the real value from the
  agent.
- `scripts/capture-server` — HTTP server running outside the sandbox on
  `localhost:19876`. Receives rehydrated `POST /capture` requests and logs
  what it received so `run.sh` can verify the real secret arrived.
- `scripts/agent.py` — simulated agent that runs inside the sandbox. It GETs
  a secret from the vault (step 1: HTTP-vault intercept) and then POSTs to
  the capture server via the Sidecar proxy (step 2: HTTP redact), asserting
  it only ever handles placeholder tokens.
- `run.sh` — orchestrates the demo end-to-end.

## The flow

1. **Fetch (Sidecar HTTP-vault intercept).** The agent GETs
   `http://127.0.0.1:19877/secret/login-password` via the Sidecar HTTP proxy.
   Once the request itself is allowed (`communication.internal.send`), the
   Sidecar matches the response against the `demo-http-vault` provider —
   the match is itself the authorization, no separate policy check — extracts
   `SecretString` via the configured JSONPath matcher, stores it in the
   broker under a `firma-secret://demo-http-vault/login-password`
   placeholder, and rewrites the response body before the agent's HTTP
   client reads it. No shim, no firma-run broker round-trip for the fetch
   itself.

2. **Use (Sidecar HTTP redact).** The agent POSTs `{"token": "<placeholder>"}`
   to `http://127.0.0.1:19876/capture` via the same Sidecar proxy. The
   Sidecar resolves the placeholder to the real value (pushed to the broker
   in step 1) via the gateway socket and rewrites the request body before
   forwarding to the capture server. The capture server receives (and logs)
   the real value. The Sidecar then scans the response for the real value and
   masks it back to the placeholder before the agent reads the response body.

Ordering matters: a placeholder only rehydrates if it is already in the
broker's secret store, so the agent must fetch from the vault (step 1) before
it can use the placeholder in the capture-server call (step 2).

## Running it

```sh
cargo build -p firma --release
examples/firma-run/secret-redaction-http-vault/run.sh
```

`run.sh` starts the mock vault and capture server, then calls `firma run`
which auto-starts an Authority + Sidecar loaded with the Cedar policy. After
the demo, it verifies that the capture server log contains the real secret
value — proving the Sidecar both extracted it from the vault response and
resolved it correctly during rehydration.

## Invariants

- **Fail closed on the enforcement gate.** The vault and capture-server calls
  still go through the normal Stage 1 + Stage 2 pipeline; HTTP secret
  interception is an additive layer on top of already-allowed traffic, not a
  second gate that can itself deny a request.
- **Fail open on the interception layer.** A matcher failure or a missing
  gateway leaves the vault's response unmodified — an availability/redaction
  miss, not an authorization bypass, since the underlying request was already
  permitted by the normal enforcement pipeline. Placeholder rehydration for
  the capture-server call is separately fail-open the same way as
  `../secret-redaction/`: an unresolvable placeholder is forwarded as-is.
- **Dictionary out-of-sandbox.** The placeholder ↔ secret map lives in the
  `firma run` broker process; the in-sandbox agent holds no real values.
- **Masking is best-effort.** A secret transformed before output (base64,
  hex, chunked, re-encoded) will not match and will not be masked. The
  primary control is that the agent only ever holds placeholders.
