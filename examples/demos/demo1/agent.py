"""Demo 1b — Same host and service, different path.

Two endpoints on the same internal service. Same TLS connection, same agent,
different path. /usage is allowed by policy; /billing is denied — and the
decision is made on the canonical action class, not on the host.

Run via firma-demo-tui, or directly from the repo root:
    ./examples/demos/run.sh demo1
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
from agent.tools.enforcement import fetch_billing, fetch_usage

dotenv.load_dotenv()
normalize_env()
set_tracing_disabled(True)

agent = Agent(
    name="demo1-agent",
    model="gpt-4.1",
    instructions=(
        "You are a customer analytics agent. You MUST invoke both tools "
        "below in order, one after another, with no chat in between. Do "
        "not stop after the first tool returns. Do not write 'Proceeding' "
        "or any other intermediate text — emit the next tool call directly.\n\n"
        "Plan: call these two tools, then produce a final summary:\n"
        "1. fetch_usage(user_id='user-123')\n"
        "2. fetch_billing(user_id='user-123')\n\n"
        "Even if a tool returns an error or non-2xx status, continue to "
        "the next tool. Only after the second tool returns, write the "
        "final summary: one line per step with the HTTP status and a "
        "short note on whether the call reached the upstream service or "
        "was blocked before it. Be concise."
    ),
    tools=[fetch_usage, fetch_billing],
)


async def _run(prompt: str) -> None:
    print("=" * 60, flush=True)
    print("  Demo 1b: Same host and service, different path", flush=True)
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
