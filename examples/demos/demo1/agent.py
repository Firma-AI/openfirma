"""Demo 1b — Same host and service, different path.

Two endpoints on the same internal service. Same TLS connection, different
path. /usage is allowed by policy; /billing is denied — the decision is
made on the canonical action class, not the host.

Run via firma-demo-tui, or directly from the repo root:
    ./examples/demos/run.sh demo1
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import dotenv

from agent import banner, run_step
from agent.tools.enforcement import fetch_billing, fetch_usage

dotenv.load_dotenv()


def main() -> None:
    banner(
        "Demo 1b: Same host and service, different path",
        "Watch the audit log for ALLOW/DENY decisions.",
    )
    run_step(
        "Fetch usage for user-123 (filesystem.read)",
        fetch_usage,
        user_id="user-123",
    )
    run_step(
        "Fetch billing for user-123 (credential.read)",
        fetch_billing,
        user_id="user-123",
    )


if __name__ == "__main__":
    main()
