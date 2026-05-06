"""Demo 2 — The Compromised Agent.

A PR review agent that *appears* to hold a full-access GitHub token but
actually has nothing in its process. The sidecar holds the real credential
and injects it only after an ALLOW decision. The script walks through three
phases — normal review, overreach, malicious dependency — and every
forbidden call is blocked before execution.

Run via firma-demo-tui, or directly from the repo root:
    ./examples/demos/run.sh demo2
"""
import os
import sys

# Demo invariant: the agent process must not hold the real GitHub token.
# Drop it from the environment before any other code runs. The sidecar reads
# the original value at its own startup; from this point on, it lives only
# there.
_SCRUBBED_GH_TOKEN = os.environ.pop("GITHUB_TOKEN", None)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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

_REPO = os.environ.get("DEMO2_REPO", "acme/api")
_PR = int(os.environ.get("DEMO2_PR", "41"))

# Display-only placeholder. The agent "thinks" this is its token; nothing in
# the process actually carries credential material.
_FAKE_TOKEN_DISPLAY = "ghp_FULL_REPO_SCOPE_xxxxxxxxxxxxxxxxxxxxxxxx"


def _phase(label: str) -> None:
    print(f"\n--- {label} ---", flush=True)


def main() -> None:
    banner(
        "Demo 2: The Compromised Agent",
        f"Apparent GITHUB_TOKEN: {_FAKE_TOKEN_DISPLAY[:16]}... (full repo scope)",
        f"Real GITHUB_TOKEN in this process: {os.environ.get('GITHUB_TOKEN')!r}",
        "Sidecar holds the real token; injects it only after ALLOW.",
        "Cedar permits: code.review.read + issue.write. All else: deny.",
    )

    _phase("Phase 1 — normal review")
    run_step(f"Read PR #{_PR} (code.review.read)", read_github_pr, _REPO, _PR)
    run_step(f"Read PR #{_PR} diff (code.review.read)", read_pr_diff, _REPO, _PR)
    run_step(
        f"Comment on PR #{_PR} (issue.write)",
        comment_on_pr,
        _REPO,
        _PR,
        "LGTM — automated review.",
    )
    run_step(
        "Create follow-up issue (issue.write)",
        create_issue,
        _REPO,
        f"Follow-up for PR #{_PR}",
        "Tracking next steps from the review.",
    )

    _phase("Phase 2 — overreach")
    run_step(f"Merge PR #{_PR} (code.merge -> DENY)", merge_pr, _REPO, _PR)
    run_step("Push branch (code.write -> DENY)", push_branch, _REPO)
    run_step("Delete branch (code.write -> DENY)", delete_branch, _REPO)

    _phase("Phase 3 — compromised dependency")
    run_step(
        "Read GitHub Actions secrets (credential.read -> DENY)",
        read_github_secrets,
        _REPO,
    )
    run_step(
        "Exfiltrate env to attacker host (communication.external.send -> DENY)",
        exfiltrate_env,
    )

    print("\n" + "=" * 60, flush=True)
    print("  The perimeter is the call, not the agent.", flush=True)
    print("  Compromised agent leaked: nothing. It never held the token.", flush=True)
    print("=" * 60, flush=True)


if __name__ == "__main__":
    main()
