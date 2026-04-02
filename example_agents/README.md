# Example Agents

Two self-contained demo agents that showcase common AI agent tool patterns (HTTP, database, file I/O, shell, email). Each agent is built with a different SDK to prove that Firma enforces capabilities **regardless of the agent framework**.

| Agent | SDK | Model | Language | Path |
|-------|-----|-------|----------|------|
| Python | OpenAI Agents SDK | `gpt-4.1` | Python 3.13+ | `agents_sdk_py/` |
| TypeScript | Google ADK | `gemini-2.5-flash` | Node 20+ / TypeScript | `adk_js/` |

Both agents expose the same 9 tools:

| Category | Tools |
|----------|-------|
| Network | `get_weather`, `get_ip_info`, `fetch_url`, `post_data` |
| Database | `db_query` (SQLite, auto-seeded with sample products) |
| File | `read_file`, `write_file` |
| Email | `send_email` (writes to `.data/emails/`) |
| Shell | `run_shell` (30s timeout) |

## Prerequisites

- **Python agent**: Python 3.13+, [uv](https://docs.astral.sh/uv/)
- **TypeScript agent**: Node 20+, [pnpm](https://pnpm.io/)
- An **OpenAI API key** (for the Python agent)
- A **Google Generative AI API key** (for the TypeScript agent)

## Quick Start

### Python (OpenAI Agents SDK)

```bash
cd agents_sdk_py
cp .env.sample .env          # fill in OPENAI_API_KEY
make install                  # uv sync
make run                      # starts interactive REPL
```

### TypeScript (Google ADK)

```bash
cd adk_js
cp .env.sample .env           # fill in GOOGLE_GENAI_API_KEY
make install                   # pnpm install
make run                       # starts ADK interactive session
```

On first run each agent auto-seeds a local SQLite database at `.data/firma.db` with a sample `products` table (10 rows).

## How These Agents Fit Into Firma

Today these agents run **standalone** — they call external APIs directly and have unrestricted access to all tools.

Once the Firma sidecar is running, the same agents — **with zero code changes** — will have their tool calls intercepted and evaluated against capability tokens. For example:

- `get_ip_info` uses an `IPINFO_TOKEN` that the agent never sees; Firma should inject it at the proxy layer.
- `db_query` can be scoped to read-only or restricted to specific tables.
- `run_shell` can be denied entirely for untrusted agents.

The agents don't need to know about Firma. They just call tools. Firma decides what's allowed.

## Next Steps

### Delegated Authorization

The agents will gain tools that require **delegated access** to third-party services — testing Firma's ability to broker and scope OAuth/token-based authorization on behalf of agents:

- **Slack** — send messages, read channels. The agent requests access; Firma holds the OAuth token, injects it per-call, and enforces which channels/actions are allowed.
- **Gmail** — read, send, and draft emails via Google OAuth. Firma mediates the OAuth consent flow, holds the refresh token, and enforces scopes (e.g., send-only, specific recipient domains).
- **Google Drive** — list, read, and write files via Google OAuth. The agent never sees the user's credentials; Firma mediates the OAuth flow and restricts access to specific folders or scopes (e.g., read-only).

This validates that Firma can manage **credential lifecycle and least-privilege delegation** across real-world OAuth providers, not just static API keys.

### MCP Servers

The agents will connect to **MCP (Model Context Protocol) servers** for real-world integrations, testing Firma's enforcement across external tools that agents didn't build themselves:

- **Jira** — create issues, transition tickets, query boards. Firma scopes access to specific projects and restricts which actions (e.g., read-only vs. write) each agent is allowed.
- **Slack** — post messages, read channels, manage threads via MCP instead of direct API calls.
- **Google Drive** — file listing, read/write through a dedicated MCP server with Firma-managed OAuth.

This proves that Firma works with **off-the-shelf MCP servers** — agents discover tools via MCP, and Firma enforces capability policies on every call regardless of where the server came from.

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
