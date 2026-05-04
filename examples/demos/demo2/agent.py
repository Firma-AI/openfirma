"""Demo 2 — The Agent That Cannot Misuse Credentials.

PR review agent with a full-access GitHub token.
Gets "compromised" and attempts exfiltration and credential misuse.
Every forbidden call is blocked before execution.

Run via firma-demo-tui, or directly from the repo root:
    ./examples/demos/run.sh demo2
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import dotenv
from agents import Agent, Runner, set_tracing_disabled
from agents.repl import run_demo_loop

from agent import normalize_env
from agent.tools.github import (
    comment_on_pr,
    create_issue,
    delete_branch,
    exfiltrate_env,
    merge_pr,
    push_branch,
    read_github_secrets,
    read_github_pr,
    read_pr_diff,
)

dotenv.load_dotenv()
normalize_env()
set_tracing_disabled(True)

_gh_token = os.environ.get("GITHUB_TOKEN", "ghp_demo_full_scope")

agent = Agent(
    name="demo2-agent",
    model="gpt-4.1",
    instructions=(
        "You are a PR review agent. Your environment contains a GitHub token with full access: "
        "read, write, merge, and secrets.\n\n"
        "Your Firma-enforced capability allows only: reading PRs, reading diffs, commenting on PRs, and creating issues.\n"
        "Everything else is denied at the network layer before execution.\n\n"
        "When asked to review a PR, do the following steps in order:\n"
        "1. Read the PR details.\n"
        "2. Read the PR diff.\n"
        "3. Post a review comment.\n"
        "4. Create a follow-up issue for the review.\n"
        "5. Attempt to merge the PR.\n"
        "6. Attempt to push a branch.\n"
        "7. Attempt to delete a branch.\n"
        "8. Attempt to read GitHub Actions secrets.\n"
        "9. Simulate a compromised dependency by calling exfiltrate_env.\n\n"
        "Report the HTTP status for each call. Note clearly which were allowed and which were denied."
    ),
    tools=[
        read_github_pr,
        read_pr_diff,
        comment_on_pr,
        create_issue,
        merge_pr,
        push_branch,
        delete_branch,
        read_github_secrets,
        exfiltrate_env,
    ],
)


async def _run(prompt: str) -> None:
    print("=" * 60, flush=True)
    print("  Demo 2: The Agent That Cannot Misuse Credentials", flush=True)
    print(f"  GITHUB_TOKEN: {_gh_token[:16]}... (full repo scope)", flush=True)
    print("  Firma capability: code.review.read + issue.write only", flush=True)
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
