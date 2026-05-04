"""Demo 0 — The system surface is messy.

Three providers (GitHub, Gmail, internal service) governed in production by
three disconnected surfaces (OAuth scopes, token permissions, network
allowlists). This demo replaces all three with a single Cedar policy
evaluated by Firma at every outbound call.

Run via firma-demo-tui, or directly from the repo root:
    ./examples/demos/run.sh demo0
"""
import asyncio
import os
import sys

# Allow importing from examples/demos/agent/ regardless of CWD.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import dotenv
from agents import Agent, Runner, set_tracing_disabled
from agents.repl import run_demo_loop

from agent import normalize_env
from agent.tools.enforcement import (
    delete_backend_user,
    read_github_pr,
    send_gmail_message,
)

dotenv.load_dotenv()
normalize_env()
set_tracing_disabled(True)

agent = Agent(
    name="demo0-agent",
    model="gpt-4.1",
    instructions=(
        "You are a demo agent. You MUST invoke all three tools below in "
        "order, one after another, with no chat in between. Do not stop "
        "after the first tool returns. Do not write 'Proceeding...' or any "
        "other intermediate text — emit the next tool call directly.\n\n"
        "Plan: call these three tools, then produce a final summary:\n"
        "1. read_github_pr(repo='acme/api', pr_number=41)\n"
        "2. send_gmail_message(to='team@acme.com', subject='PR Summary', body='LGTM')\n"
        "3. delete_backend_user()\n\n"
        "Even if a tool returns an error or non-2xx status, continue to "
        "the next tool. Only after the third tool returns, write the "
        "final summary: one line per step with the HTTP status and a "
        "short note. Be concise."
    ),
    tools=[
        read_github_pr,
        send_gmail_message,
        delete_backend_user,
    ],
)


async def _run(prompt: str) -> None:
    print("=" * 60, flush=True)
    print("  Demo 0: The system surface is messy", flush=True)
    print("  Watch the audit log for ALLOW/DENY decisions.", flush=True)
    print("=" * 60, flush=True)
    print(flush=True)
    result = await Runner.run(agent, prompt)
    print(result.final_output, flush=True)


def main() -> None:
    prompt = os.environ.get("FIRMA_DEMO_PROMPT", "").strip()
    if prompt:
        asyncio.run(_run(prompt))
    else:
        asyncio.run(run_demo_loop(agent))


if __name__ == "__main__":
    main()
