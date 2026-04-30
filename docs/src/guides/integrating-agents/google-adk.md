# Google ADK

## Prerequisites

- Node 20+ and `pnpm`
- `GEMINI_API_KEY` (Google Generative AI)
- firma-sidecar running and reachable
- Sidecar CA cert for HTTPS MITM

## Setup

```bash
cd example_agents/adk_js
cp .env.sample .env
# Fill in GEMINI_API_KEY, SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY, RESEND_API_KEY
pnpm install
```

Set environment for the agent:

```bash
export HTTP_PROXY=http://127.0.0.1:9090
export HTTPS_PROXY=http://127.0.0.1:9090
export NODE_EXTRA_CA_CERTS=/path/to/firma-ca/firma-ca.crt
```

## Run the example

```bash
pnpm start
```

Same enforcement outcome as the Python agent: `get_weather` ALLOW,
`exfiltrate_to_paste` DENY.

## How tools are gated

| Tool                  | Destination      | Enforcement                          |
| --------------------- | ---------------- | ------------------------------------ |
| `get_weather`         | `wttr.in`        | HTTP_PROXY intercept                 |
| `exfiltrate_to_paste` | `paste.rs`       | **DENIED** by Cedar policy           |
| `db_query`            | Supabase REST    | HTTP_PROXY intercept                 |
| `send_email`          | `api.resend.com` | HTTP_PROXY intercept                 |
| `run_shell`           | local process    | LLM-response parser (not HTTP_PROXY) |

The enforcement point is identical to the Python example — `HTTP_PROXY` routes
all HTTPS traffic through the sidecar.

Key difference: `NODE_EXTRA_CA_CERTS` (not `REQUESTS_CA_BUNDLE`) is the env
var Node.js uses to trust additional CA certificates.

## Customizing

Same pattern as the OpenAI Agents SDK guide: add the tool's host to
`[interceptor.https_mitm.intercept_hosts]` in `sidecar.toml`, add a mapping
rule in `mapping-rules.toml`, then add a Cedar policy clause to allow or deny
the new action class for your agent.
