---
name: open-pr
description: Open a GitHub pull request for OpenFirma. Use whenever you are asked to open a PR.
---

# Open PR

Use this workflow whenever you are asked to open a GitHub pull request for
OpenFirma.

## Workflow

1. Inspect the repository state and active VCS before touching PR state.
2. Inspect the revision stack that will be included in the PR.
3. If the working copy is dirty, the stack is mixed, or the target history is
   already under review, load and follow the
   [`commit-guidelines`](../commit-guidelines/SKILL.md) skill before
   continuing.
4. Inspect bookmarks or branches and remotes.
5. Read the [PR template](../../.github/pull_request_template.md).
6. Load and follow the [`verify`](../verify/SKILL.md) skill before pushing or opening the PR.
7. Push the review head to the correct remote.
8. Open the PR with `gh`.
9. Verify the final PR body, title, base, and head.
10. Ask the user whether they want an adversarial PR review.

For `jj` repositories, create or update a bookmark that points at the intended
review tip before pushing it to the selected remote.

## Verify after creation

After creating the PR, inspect it with `gh pr view` and confirm:

- title matches repo style
- base branch is correct
- head branch or bookmark is correct
- body follows the PR template
- all intended commits are included

If the body does not match what you requested, fix it immediately instead of
assuming the create or edit step worked.

## Optional adversarial review

After the PR is open and verified, ask the user whether they want an
adversarial PR review.

If they say yes:

- launch a fresh sub-agent session;
- give the reviewer only the PR URL
- do not preload the reviewer with implementation history, local rationale, or
  how the change was constructed
- ask it to review like an independent reviewer and prioritize bugs,
  regressions, type safety, risky assumptions, and missing tests

The goal is to simulate a skeptical reviewer who only sees the PR, not the
authoring process behind it.

## Output

Report the PR URL.
