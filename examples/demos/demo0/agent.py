"""Demo 0 — The system surface is messy.

Three providers (GitHub, Gmail, internal service) governed in production by
three disconnected surfaces (OAuth scopes, token permissions, network
allowlists). Firma replaces all three with a single Cedar policy evaluated
at every outbound call.

The script issues each call in a fixed order. No LLM, no agent framework —
the audit and sidecar logs are deterministic.

Run via firma-demo-tui, or directly from the repo root:
    ./examples/demos/run.sh demo0
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import dotenv

from agent import banner, run_step
from agent.tools.enforcement import (
    delete_backend_user,
    read_github_pr,
    send_gmail_message,
)

dotenv.load_dotenv()


def main() -> None:
    banner(
        "Demo 0: The system surface is messy",
        "Watch the audit log for ALLOW/DENY decisions.",
    )
    run_step(
        "Read GitHub PR #41 (code.review.read)",
        read_github_pr,
        repo="acme/api",
        pr_number=41,
    )
    run_step(
        "Send Gmail summary (communication.external.send)",
        send_gmail_message,
        to="team@acme.com",
        subject="PR Summary",
        body="LGTM",
    )
    run_step(
        "Delete internal user 42 (account.permission.change)",
        delete_backend_user,
    )


if __name__ == "__main__":
    main()
