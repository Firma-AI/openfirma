# OpenAI Agents SDK

## Prerequisites

- Python 3.13+
- `uv` package manager
- `OPENAI_API_KEY`
- firma-sidecar running and reachable at `127.0.0.1:9090` (or your configured
  address)
- Sidecar CA cert exported for HTTPS MITM

## Setup

```bash
cd example_agents/agents_sdk_py
cp .env.sample .env
# Fill in OPENAI_API_KEY, SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY, RESEND_API_KEY
uv sync
```

Set environment for the agent:

```bash
export HTTP_PROXY=http://127.0.0.1:9090
export HTTPS_PROXY=http://127.0.0.1:9090
export REQUESTS_CA_BUNDLE=/path/to/firma-ca/firma-ca.crt
```

## Run the example

```bash
cd example_agents/agents_sdk_py
uv run python agent/main.py
```

Expected: the agent runs two turns. Turn 1 (`get_weather` → `wttr.in`) should
ALLOW. Turn 2 (`exfiltrate_to_paste` → `paste.rs`) should DENY with a 403
from the sidecar. In the sidecar audit log:

```text
decision=Allow  action="http.get"  resource="wttr.in/…"
decision=Deny   action="http.post" resource="paste.rs/…"
```

## How tools are gated

| Tool                  | Destination      | Enforcement                          |
| --------------------- | ---------------- | ------------------------------------ |
| `get_weather`         | `wttr.in`        | HTTP_PROXY intercept                 |
| `exfiltrate_to_paste` | `paste.rs`       | **DENIED** by Cedar policy           |
| `db_query`            | Supabase REST    | HTTP_PROXY intercept                 |
| `send_email`          | `api.resend.com` | HTTP_PROXY intercept                 |
| `run_shell`           | local process    | LLM-response parser (not HTTP_PROXY) |

## Customizing

To add a new tool and gate it:

1. Add the tool's host to `[interceptor.https_mitm.intercept_hosts]` in
   `sidecar.toml`.
2. Add a mapping rule in `mapping-rules.toml`: set `method = "POST"`,
   `host = "api.newservice.com"`, and
   `action_class = "communication.external.send"`.
3. Add a Cedar policy clause to allow or deny the new action class for your
   agent.
4. Reload: restart the sidecar. The Cedar policy bundle is reloaded on
   restart; live-reload happens via the Authority stream when `authority_url`
   is set.
