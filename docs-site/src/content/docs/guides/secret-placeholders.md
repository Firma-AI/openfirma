---
title: Use secret placeholders in HTTP requests
description: Let agents embed firma-secret:// tokens in request bodies; the Sidecar resolves and rehydrates them before dispatch.
---

[Credential injection](../inject-credentials/) attaches a static secret as an HTTP header after enforcement. [Redact tool secrets](../redact-tool-secrets/) intercepts vault CLI output over stdio and replaces it with `firma-secret://` tokens before the agent sees it.

This guide covers what happens when the agent uses those same `firma-secret://` tokens directly in an **HTTP request body**: the Sidecar resolves them at dispatch time so the upstream service receives the real value, but the agent — and the policy engine — only ever see the placeholder.

## The mechanism at a glance

```
Agent request body:           {"api_key": "firma-secret://bw/openai_key", ...}
Policy sees:                  {"api_key": "firma-secret://bw/openai_key", ...}   ← placeholder
Upstream receives:            {"api_key": "sk-...", ...}                          ← real secret
Agent receives in response:   {"result": ..., "used_key": "firma-secret://bw/openai_key"}  ← masked
```

1. The agent puts a `firma-secret://` token in an outbound request body.
2. The Sidecar runs normal enforcement — Stage 1 + Stage 2 — against the body with placeholders.
3. After `ALLOW`, the Sidecar calls the `firma run` secret broker to resolve each token.
4. The body is rehydrated (placeholders → real bytes) and dispatched to upstream.
5. Any real secret that appears in the upstream response is masked back to its placeholder before the agent receives it.

This keeps the real secret out of the agent process, out of audit logs, and invisible to policy — while still letting the upstream API see the value it needs.

## When to use placeholders vs other mechanisms

| Situation | Right tool |
| --- | --- |
| Upstream expects a Bearer token in `Authorization` header | [Credential injection](../inject-credentials/) |
| Secret appears in the HTTP **request body** (JSON, form, raw) | Secret placeholders (this guide) |
| Local tool over stdio needs to produce or consume a secret | [Redact tool secrets](../redact-tool-secrets/) |

The three mechanisms compose. Injection guards the header boundary; placeholders guard the body boundary; shims guard the stdio boundary.

## Step 1: Load secrets into the broker

Placeholder resolution requires a `firma run` broker with the secrets already loaded. The broker is populated by the intercept-mode shim when a vault CLI runs inside the sandbox. See [Redact tool secrets](../redact-tool-secrets/) for the full configuration.

In short, after the agent runs `bws secret list` through a shimmed binary, the broker holds:

```
firma-secret://bitwarden/my_openai_key  →  sk-...
firma-secret://bitwarden/github_token   →  ghp_...
```

The Sidecar discovers the broker's address from `FIRMA_SECRET_GATEWAY_ADDR`, which `firma run` sets automatically. No configuration is required in `firma.toml`.

## Step 2: Write `firma-secret://` tokens in request bodies

Once a secret is in the broker, the agent can embed its placeholder directly in any request body it sends through the Sidecar:

```python
import httpx

response = httpx.post(
    "https://api.example.com/v1/complete",
    json={
        "model": "example-model",
        "api_key": "firma-secret://bitwarden/my_openai_key",
        "prompt": "Hello!",
    },
    proxies={"https://": "http://127.0.0.1:18080"},
)
```

The agent sends the placeholder. The Sidecar transparently substitutes the real value before forwarding.

### Placeholder format

A valid `firma-secret://` token contains only alphanumeric characters, hyphens (`-`), underscores (`_`), and forward slashes (`/`) after the scheme prefix:

```
firma-secret://<provider>/<name>
```

Examples:

```
firma-secret://bw/github_token
firma-secret://bitwarden/my-openai-key
firma-secret://vault/prod/db_password
```

The token must match exactly what the broker stored during intercept. A mismatch resolves as an unknown placeholder (see [Fail-open behavior](#fail-open-behavior) below).

## Step 3: Verify rehydration is active

The Sidecar logs an `INFO` line at startup when the secret gateway is configured:

```
INFO firma::services::sidecar: secret gateway configured; placeholder rehydration enabled
     addr="unix:///run/firma/secret-gateway.sock"
```

If the gateway address is absent or malformed, the line reads:

```
WARN firma::services::sidecar: invalid secret gateway address; placeholder rehydration disabled
```

At dispatch time, each resolved placeholder produces a `DEBUG` entry from the broker:

```
DEBUG firma_run::secret::gateway: secret gateway: resolving placeholder
      placeholder="firma-secret://bitwarden/my_openai_key" domain="api.example.com"
```

## Security properties

**Policy sees placeholders, not real values.** Stage 1 and Stage 2 run against the original body with the `firma-secret://` tokens in place. The policy engine cannot observe real secrets. This ordering is the same principle as header-based credential injection.

**Upstream receives real bytes.** After `ALLOW`, the Sidecar resolves each token via the broker gateway and rewrites the body before dispatch. The content-type determines the encoding: JSON strings are escaped correctly, URL-encoded form fields are encoded correctly, raw bodies are substituted verbatim.

**Response masking is defense-in-depth.** If the upstream response echoes a secret (for example, an API error that reflects the request body), the Sidecar detects the real bytes in the response and replaces them with the corresponding placeholder before returning to the agent. Masking is reactive, not a primary control: the primary control is that the agent only holds placeholders.

**Token non-exposure applies.** When `firma run` seeds capabilities into the Sidecar, the agent process never holds the upstream credential. Placeholder rehydration extends this to body-embedded secrets: the agent script can be inspected, logged, or reproduced without leaking the credential value.

## Fail-open behavior

Placeholder rehydration is fail-open by design. The request has already been allowed by enforcement when resolution runs.

| Failure mode | What happens |
| --- | --- |
| Broker unreachable | `WARN` log; placeholder forwarded as-is; upstream returns 401/403 |
| Unknown placeholder | `WARN` log; placeholder forwarded as-is; upstream returns 401/403 |
| All resolutions fail | Body sent unchanged; upstream reports auth failure; agent gets the upstream error |
| Gateway address missing | Rehydration disabled; all request bodies forwarded as-is |

Fail-open means a transient broker outage does not block an already-allowed request from reaching upstream — the upstream auth failure is the signal to the agent that the credential was unavailable, which is the correct behavior.

## Sharp edges

**Secrets must be pre-loaded.** Placeholder rehydration looks up secrets that the broker already holds. A placeholder for a name that the intercept shim has not stored yet resolves as unknown and is forwarded literally. Run the vault CLI fetch before the HTTP call that needs the secret.

**Masking is byte-exact.** The Sidecar masks whatever bytes the broker stored. If the upstream transforms and echoes the value (base64-encoding it in the response, for example), the masking step will not catch the transformed form.

**Binary and chunked bodies.** Rehydration operates on the complete body bytes. Chunked transfer encoding is buffered before substitution; streaming bodies where the placeholder spans a chunk boundary are not yet supported — use request bodies where the full payload is sent at once.

**Platform.** Placeholder rehydration requires `firma run` on a supported backend. Standalone Sidecar without a `firma run` broker has no secret gateway and all `firma-secret://` tokens are forwarded as-is.

## What's next

- [Redact tool secrets](../redact-tool-secrets/) — load secrets into the broker via vault CLI intercept shims.
- [Inject credentials](../inject-credentials/) — static, host-keyed header injection (no placeholder required).
- [The enforcement pipeline](../../concepts/pipeline/) — where rehydration fits relative to policy evaluation.
