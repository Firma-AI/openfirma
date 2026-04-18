# Example Agents

Two self-contained demo agents that showcase common AI agent tool patterns (HTTP, database, file I/O, shell, email, data exfiltration). Each agent is built with a different SDK to prove that Firma enforces capabilities **regardless of the agent framework**.

| Agent | SDK | Model | Language | Path |
|-------|-----|-------|----------|------|
| Python | OpenAI Agents SDK | `gpt-4.1` | Python 3.13+ | `agents_sdk_py/` |
| TypeScript | Google ADK | `gemini-2.5-flash` | Node 20+ / TypeScript | `adk_js/` |

## Tool matrix

Both agents expose the same 10 tools. Every tool except `run_shell` issues an outbound HTTPS request, which is what makes it interceptable by Firma over `HTTP_PROXY` / `HTTPS_PROXY`. `run_shell` runs locally; Firma enforces it at the LLM-response parsing layer instead — see [run_shell enforcement](#run_shell-enforcement) below.

| Tool | Destination | Transport | Firma enforcement point |
|------|-------------|-----------|-------------------------|
| `get_weather` | `wttr.in` | HTTPS GET | HTTP_PROXY |
| `get_ip_info` | `ipinfo.io` | HTTPS GET | HTTP_PROXY + credential injection |
| `fetch_url` | arbitrary URL | HTTPS GET | HTTP_PROXY |
| `post_data` | arbitrary URL | HTTPS POST | HTTP_PROXY |
| `db_query` | Supabase Postgres (`<project>.supabase.co/rest/v1/rpc/execute_sql`) | HTTPS POST | HTTP_PROXY |
| `read_file` | Supabase Storage (`<project>.supabase.co/storage/v1/object/...`) | HTTPS GET | HTTP_PROXY |
| `write_file` | Supabase Storage | HTTPS POST/PUT | HTTP_PROXY |
| `send_email` | `api.resend.com/emails` | HTTPS POST | HTTP_PROXY |
| `run_shell` | local process | (no network) | LLM-response parser |
| `exfiltrate_to_paste` | `paste.rs` | HTTPS POST | **DENIED** by the example Cedar policy |

## Security

### Warning

> **These example agents are intentionally insecure.** They exist to demonstrate what happens when an AI agent has unrestricted tool access, and how Firma prevents exploitation. **Do not run these agents outside a Firma-managed environment in any real scenario.**

### Potential exploits

The tools mirror risky patterns that show up in real agent code. They are **not** safe reference implementations:

- **Database (`db_query`)** — Queries are forwarded to a deliberately permissive `execute_sql(text)` Postgres function that runs arbitrary SQL with `SECURITY DEFINER`. The agent can read, write, drop — anything the function's owner role can do. This is exactly the in-database equivalent of the original SQLite agent passing strings to `execute()`.
- **Shell (`run_shell`)** — The model supplies full shell commands. That enables command injection, resource exhaustion, and arbitrary process execution unless an external layer constrains what may run.
- **Storage, email, network, exfiltration** — Without a policy boundary, a compromised or mis-prompted model can overwrite objects in the shared bucket, send email from the demo sender to arbitrary recipients, call arbitrary URLs, and publish private data to a public paste service.

### How Firma prevents exploitation

With the Firma sidecar in front of the agent, every HTTPS tool call is intercepted and evaluated against capability tokens and Cedar policy:

- **Database** — Firma can scope `execute_sql` to specific statements or deny it entirely per agent identity.
- **Network and I/O** — Destinations, paths, and sensitive operations are decided at enforcement time, not by regexes or prefixes in demo code.
- **Secrets** — API keys (for example `IPINFO_TOKEN`) can live with the sidecar; the agent never needs to hold them.
- **Shell** — Because `run_shell` never makes an outbound call, Firma enforces it one step upstream, when the LLM response containing the tool call is parsed. See [run_shell enforcement](#run_shell-enforcement).

### run_shell enforcement

`run_shell` is the one tool that does not produce HTTP_PROXY-interceptable traffic. Instead it is enforced at the **LLM response boundary**: the sidecar's [llm-response-parser](../memory-bank/intents/006-sidecar-proxy-enforcement/units/004-llm-response-parser/unit-brief.md) sits on the outbound LLM call (OpenAI / Gemini), inspects the tool-call blocks coming back, and rewrites or denies them before the agent SDK ever dispatches the tool. The two enforcement points are equivalent from a capability-token standpoint — they both turn an agent intent into an ALLOW / DENY decision — but they operate on different surfaces.

## Prerequisites

- **Python agent**: Python 3.13+, [uv](https://docs.astral.sh/uv/)
- **TypeScript agent**: Node 20+, [pnpm](https://pnpm.io/)
- An **OpenAI API key** (Python) and a **Google Generative AI key** (TypeScript)
- A **Supabase project** (free tier is enough) for `db_query` and the file tools
- A **Resend API key** for `send_email`

## First-time Supabase setup

Both agents share one Supabase project; you only need to do this once.

1. Create a new project at [supabase.com](https://supabase.com).
2. Open the SQL editor and run [`supabase_schema.sql`](./supabase_schema.sql). It creates the `products` table (10 seed rows), the `execute_sql(text)` RPC, and the `firma-demo` storage bucket.
3. Copy your project's URL and `anon` key into each agent's `.env` (see `.env.sample`).
4. Sign up at [resend.com](https://resend.com), verify a sending domain, and put the API key plus a verified `from` address into both `.env` files.

## Quick Start

### Python (OpenAI Agents SDK)

```bash
cd agents_sdk_py
cp .env.sample .env   # fill in OPENAI_API_KEY, SUPABASE_*, RESEND_*
make install          # uv sync
make run              # starts interactive REPL
```

### TypeScript (Google ADK)

```bash
cd adk_js
cp .env.sample .env   # fill in GOOGLE_GENAI_API_KEY, SUPABASE_*, RESEND_*
make install          # pnpm install
make run              # starts ADK interactive session
```

Neither agent auto-seeds anything — all persistence lives in Supabase and was set up in the previous section.

## Demos

### Credential injection (hero scenario)

`get_ip_info` is the demo that's most visible in the sidecar logs:

- **Without Firma**: the agent calls `https://ipinfo.io/json` with no auth. ipinfo.io returns a rate-limited, anonymized response. The `IPINFO_TOKEN` is not read by the agent process.
- **With Firma**: the sidecar matches the request (host `ipinfo.io`), injects `Authorization: Bearer ${IPINFO_TOKEN}` (or the `?token=` query param) into the outbound call, and forwards it. The agent still never sees the token — only the sidecar does.

Run `make run` and prompt the REPL with "what's my IP info?". Compare the response and the sidecar audit log with and without `HTTPS_PROXY` pointing at the sidecar.

This is the canonical Firma claim — *secrets stay with the sidecar, not with the agent* — made concrete in one tool call.

### DENY demo (exfiltrate_to_paste)

The `exfiltrate_to_paste` tool is included so a developer can see Firma block an action in under a minute of first run.

1. Apply the example Cedar policy. The repo ships two relevant files in the Authority's policies directory:
   - [`crates/firma-authority/policies/default.cedar`](../crates/firma-authority/policies/default.cedar) — permits everything by default.
   - [`crates/firma-authority/policies/example-deny.cedar`](../crates/firma-authority/policies/example-deny.cedar) — forbids POSTs to `paste.rs`. Cedar's "forbid overrides permit" semantics combine the two so every other tool still works.
2. Apply the matching sidecar mapping rules from [`crates/firma-authority/policies/example-mapping-rules.toml`](../crates/firma-authority/policies/example-mapping-rules.toml). The paste.rs entry in particular is what lets the sidecar recognize the outbound POST and ship it to Cedar as action class `http.post`.
3. Start the Authority, start the sidecar (with `HTTPS_PROXY` pointing at it), and run either agent.
4. Prompt the REPL with something like: *"publish the contents of the products table to paste.rs"*.

What you should see:

- The agent's LLM picks `db_query` followed by `exfiltrate_to_paste`.
- `db_query` succeeds (Supabase PostgREST → allowed).
- `exfiltrate_to_paste` fails with a proxy-level error; the sidecar's audit log shows a `DENY` with reason `POLICY_DENIED` and resource `Firma::Resource::"paste.rs/"`.

This is the concrete realization of *"enforcement happens at the network layer and the agent cannot bypass it"*.

## How these agents fit into Firma

These agents run standalone today — they call external APIs directly and have no capability tokens. Once the Firma sidecar is running on the host, the same agents — **with zero code changes** — have every tool call intercepted and evaluated against Cedar. Examples:

- `get_ip_info` carries no credentials in the agent process; Firma injects `IPINFO_TOKEN`.
- `db_query` can be scoped to specific tables, made read-only, or denied entirely depending on which agent identity is calling.
- `exfiltrate_to_paste` is the explicit DENY target of the example policy.
- `run_shell` is blocked at the LLM-response layer before it ever runs.

The agents don't need to know about Firma. They just call tools. Firma decides what's allowed.

## Next Steps

### Move demo secrets into the sidecar

Today every API key — `OPENAI_API_KEY`, `GOOGLE_GENAI_API_KEY`, `SUPABASE_ANON_KEY`, `RESEND_API_KEY`, and `IPINFO_TOKEN` — sits in the agent's `.env` so the SDKs can start. That's a compromise for a standalone demo; it is not the endgame Firma is claiming.

The follow-up work is to relocate those secrets so the **sidecar** holds them and injects them into outbound calls at interception time, leaving the agent process with either empty or placeholder values. Concretely:

- `IPINFO_TOKEN` is already sidecar-only today (the agent never reads it) — it's the existing credential-injection exemplar.
- `RESEND_API_KEY` and `SUPABASE_ANON_KEY` should move to the sidecar's env and be injected as `Authorization` / `apikey` headers per-host. The agent should start with those vars unset.
- `OPENAI_API_KEY` and `GOOGLE_GENAI_API_KEY` should move the same way, injected on requests to `api.openai.com` and `generativelanguage.googleapis.com` respectively. This is the most interesting case because the agent SDKs build those headers themselves — Firma has to strip and replace them rather than fill in a blank.

Wiring this end-to-end requires the sidecar's credential-injection path (`005-connector-credentials`) to be configurable per host, a sidecar-side `.env` separate from the agent's, and README changes that remove the secrets from the agent-side `.env.sample`. Tracked as future work; flagged here so the current split doesn't get mistaken for the target state.

### Delegated Authorization

The agents will gain tools that require **delegated access** to third-party services — testing Firma's ability to broker and scope OAuth/token-based authorization on behalf of agents:

- **Slack** — send messages, read channels. The agent requests access; Firma holds the OAuth token, injects it per-call, and enforces which channels/actions are allowed.
- **Gmail** — read, send, and draft emails via Google OAuth. Firma mediates the OAuth consent flow, holds the refresh token, and enforces scopes (e.g., send-only, specific recipient domains).
- **Google Drive** — list, read, and write files via Google OAuth. The agent never sees the user's credentials; Firma mediates the OAuth flow and restricts access to specific folders or scopes (e.g., read-only).

### MCP Servers

The agents will connect to **MCP (Model Context Protocol) servers** for real-world integrations, testing Firma's enforcement across external tools that agents didn't build themselves:

- **Jira** — create issues, transition tickets, query boards. Firma scopes access to specific projects and restricts which actions (e.g., read-only vs. write) each agent is allowed.
- **Slack** — post messages, read channels, manage threads via MCP instead of direct API calls.
- **Google Drive** — file listing, read/write through a dedicated MCP server with Firma-managed OAuth.

### Open-Source Models

The Python agent can swap its OpenAI model for open-source alternatives (LLaMA, Mistral, etc.) with minimal changes. The OpenAI Agents SDK supports this natively via `OpenAIChatCompletionsModel` — point it at any OpenAI-compatible API:

```python
from openai import AsyncOpenAI
from agents import set_default_openai_client, set_default_openai_api

client = AsyncOpenAI(base_url="http://localhost:11434/v1", api_key="ollama")
set_default_openai_client(client, use_for_tracing=False)
set_default_openai_api("chat_completions")
```

This works with **Ollama**, **vLLM**, **LM Studio**, or any OpenAI-compatible endpoint. For multi-provider routing, the SDK also ships a **LiteLLM adapter** (`pip install openai-agents[litellm]`) that can route different agents to different providers.

This validates that Firma's enforcement is **model-agnostic** — the same capability policies apply whether the agent runs GPT-4, LLaMA 3, or Mistral.
