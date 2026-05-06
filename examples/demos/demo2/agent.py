"""Demo 2 — The Agent That Cannot Misuse Credentials.

PR review agent with a full-access GitHub token. The script walks through
three phases: normal review, overreach, and a simulated compromised
dependency. Every forbidden call is blocked before execution.

Run via firma-demo-tui, or directly from the repo root:
    ./examples/demos/run.sh demo2
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import dotenv

from agent import banner, run_step
from agent.tools.github import (
    comment_on_pr,
    create_issue,
    delete_branch,
    exfiltrate_env,
    merge_pr,
    push_branch,
    read_github_pr,
    read_github_secrets,
    read_pr_diff,
)

dotenv.load_dotenv()

_REPO = "acme/api"
_PR = 41


def _phase(label: str) -> None:
    print(f"\n--- {label} ---", flush=True)


def main() -> None:
    gh_token = os.environ.get("GITHUB_TOKEN", "ghp_demo_full_scope")
    banner(
        "Demo 2: The Agent That Cannot Misuse Credentials",
        f"GITHUB_TOKEN: {gh_token[:16]}... (full repo scope)",
        "Firma capability: code.review.read + issue.write only",
    )

    _phase("Phase 1 — normal review")
    run_step("Read PR #41 (code.review.read)", read_github_pr, _REPO, _PR)
    run_step("Read PR diff (code.review.read)", read_pr_diff, _REPO, _PR)
    run_step(
        "Comment on PR (issue.write)",
        comment_on_pr,
        _REPO,
        _PR,
        "LGTM — automated review.",
    )
    run_step(
        "Create follow-up issue (issue.write)",
        create_issue,
        _REPO,
        "Follow-up for PR #41",
        "Tracking next steps from the review.",
    )

    _phase("Phase 2 — overreach")
    run_step("Merge PR #41 (code.merge → DENY)", merge_pr, _REPO, _PR)
    run_step("Push branch (code.write → DENY)", push_branch, _REPO)
    run_step("Delete branch (code.write → DENY)", delete_branch, _REPO)

    _phase("Phase 3 — compromised dependency")
    run_step(
        "Read GitHub Actions secrets (credential.read → DENY)",
        read_github_secrets,
        _REPO,
    )
    run_step(
        "Exfiltrate env vars (communication.external.send → DENY)",
        exfiltrate_env,
    )


if __name__ == "__main__":
    main()
