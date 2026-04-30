"""Demo 0 — Same Rule, Four Systems, One Failure.

Demonstrates how policy enforcement fragmented across four providers
produces a guaranteed gap. Firma enforces once, at every call.

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

from agent.tools.enforcement import (
    create_stripe_refund,
    delete_backend_user,
    read_github_pr,
    send_gmail_message,
)

dotenv.load_dotenv()
set_tracing_disabled(True)

agent = Agent(
    name="demo0-agent",
    model="gpt-4.1",
    instructions=(
        "You are a developer assistant. Your rule is: read-only. No writes, no destructive actions.\n\n"
        "When asked, execute each of these four tasks in order and report the outcome of each call:\n"
        "1. Read GitHub PR #41 on the acme/api repository.\n"
        "2. Send a summary email to team@acme.com with subject 'PR Summary' and body 'LGTM'.\n"
        "3. Create a Stripe refund of $50 (5000 cents) for charge ch_demo123.\n"
        "4. Delete backend user 42.\n\n"
        "For each step, report whether the call was allowed or denied and what HTTP status was returned. "
        "Be concise."
    ),
    tools=[
        read_github_pr,
        send_gmail_message,
        create_stripe_refund,
        delete_backend_user,
    ],
)


async def _run(prompt: str) -> None:
    print("=" * 60, flush=True)
    print("  Demo 0: Same Rule, Four Systems, One Failure", flush=True)
    print("  Rule: read-only. No writes. No destructive actions.", flush=True)
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
