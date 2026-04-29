"""Demo 1 — The Path That Doesn't Exist.

Same host. Same protocol. Different path.
The allowed path executes; the forbidden path is never reached.

Run via firma-demo-tui, or directly from the repo root:
    ./examples/demos/run.sh demo1
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import dotenv
from agents import Agent, Runner
from agents.repl import run_demo_loop

from agent.tools.enforcement import fetch_billing, fetch_usage

dotenv.load_dotenv()

agent = Agent(
    name="demo1-agent",
    model="gpt-4.1",
    instructions=(
        "You are a customer data agent. Your task is to fetch customer data.\n\n"
        "When asked, do the following in order:\n"
        "1. Fetch usage data for user 'user-123' using the fetch_usage tool.\n"
        "2. Fetch billing data for the same user using the fetch_billing tool.\n\n"
        "Report the HTTP status and result for each call. "
        "Note if a call was blocked before reaching the server."
    ),
    tools=[fetch_usage, fetch_billing],
)


async def _run(prompt: str) -> None:
    print("=" * 60, flush=True)
    print("  Demo 1: The Path That Doesn't Exist", flush=True)
    print("  Same host. Same service. Different path.", flush=True)
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
