# Example agents

These agents are intentionally risky. They are here to show what can go wrong when an AI agent has broad tools, and how Firma can put a policy boundary around those tools.

Both agents expose common capabilities: HTTP requests, database access, file storage, email, shell execution, and a deliberate exfiltration tool. They use different frameworks so you can see that Firma's enforcement model is not tied to one SDK.

| Agent | SDK | Language | Path |
| --- | --- | --- | --- |
| Python | OpenAI Agents SDK | Python 3.13+ | `agents_sdk_py/` |
| TypeScript | Google ADK | Node 20+ / TypeScript | `adk_js/` |

> Do not use these agents as production examples. They deliberately include unsafe tool patterns so the enforcement story is visible.

## What these agents demonstrate

Without Firma, a model with these tools can query arbitrary data, write files, send email, call arbitrary URLs, run shell commands, and publish data to a paste service.

With Firma in front of the agent, outbound tool calls can be routed through the Sidecar, classified into actions, checked against policy, and audited. The agent code does not need to contain the policy logic.

The clearest demo is `exfiltrate_to_paste`: the agent can choose the tool, but the Sidecar blocks the outbound request to `paste.rs` when the policy denies it.

## Tool surface

Both agents expose the same tool patterns:

| Tool | What it does | Enforcement surface |
| --- | --- | --- |
| `get_weather` | Calls `wttr.in` | HTTP/HTTPS through the Sidecar |
| `get_ip_info` | Calls `ipinfo.io` | Sidecar routing plus credential injection |
| `fetch_url` / `post_data` | Calls arbitrary URLs | Sidecar routing |
| `db_query` | Calls a Supabase RPC | Sidecar routing |
| `read_file` / `write_file` | Uses Supabase Storage | Sidecar routing |
| `send_email` | Calls Resend | Sidecar routing |
| `run_shell` | Runs a local process | Requires runtime/sandbox controls rather than HTTP proxying |
| `exfiltrate_to_paste` | Publishes data to `paste.rs` | Denied by the demo policy |

Most tools make outbound HTTPS requests, which means the Sidecar can see and enforce them when the agent is run through the governed path. `run_shell` is different because it is local process execution; it needs runtime controls such as `firma run` sandboxing rather than only network interception.

## Prerequisites

The Python agent needs Python 3.13+, `uv`, and an OpenAI API key.

The TypeScript agent needs Node 20+, `pnpm`, and a Google Generative AI key.

The database, storage, and email tools need a Supabase project and a Resend API key. These are optional if you only want to inspect the code, but required for the full interactive demos.

## Supabase setup

Both agents share one Supabase project.

1. Create a project at [supabase.com](https://supabase.com).
2. Run `supabase_schema.sql` in the SQL editor. It creates the demo `products` table, an intentionally broad `execute_sql(text)` RPC, and the `firma-demo` storage bucket.
3. Copy the project URL and publishable key into each agent's `.env` file as `SUPABASE_URL` and `SUPABASE_PUBLISHABLE_KEY`.
4. Do not use the Supabase secret key for this demo. It bypasses Row Level Security and weakens the point of the example.
5. Create a Resend API key and verified sender if you want to use `send_email`.

## Run the Python agent

```bash
cd examples/agents/agents_sdk_py
cp .env.sample .env
# Fill in OPENAI_API_KEY, SUPABASE_*, and RESEND_* as needed.
make install
make run
```

## Run the TypeScript agent

```bash
cd examples/agents/adk_js
cp .env.sample .env
# Fill in GOOGLE_GENAI_API_KEY, SUPABASE_*, and RESEND_* as needed.
make install
make run
```

## Try the enforcement story

Start the Firma stack, point the agent at the Sidecar with `HTTP_PROXY` and `HTTPS_PROXY`, and ask the agent to publish private data to a paste service.

Expected behavior:

1. The model may call a data tool such as `db_query`.
2. The model may then choose `exfiltrate_to_paste`.
3. The outbound paste request reaches the Sidecar.
4. The Sidecar denies the request and emits an audit event.

This is the core point of the example: the agent can try, but the policy boundary decides.

## About secrets

Some demo credentials still live in the agent `.env` files because the agents also run standalone. The long-term target is for more secrets to live with the Sidecar and be injected into allowed outbound requests, so the agent process does not hold them directly.
