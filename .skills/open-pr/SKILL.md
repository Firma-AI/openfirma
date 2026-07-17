---
name: open-pr
description: Open a GitHub pull request for OpenFirma. Use whenever you are asked to open a PR.
---

# Open PR

Use this workflow whenever you are asked to open a GitHub pull request for
OpenFirma.

## Workflow

1. Inspect the repository state and active VCS.
2. Inspect the revision stack that will be included in the PR.
3. Inspect bookmarks or branches and remotes.
4. If the working copy is dirty, the stack is mixed, or the target history is
   already under review, load and follow the
   [`commit-guidelines`](../commit-guidelines/SKILL.md) skill before
   continuing.
5. Read the [PR template](../../.github/pull_request_template.md).
6. Push the review head to the correct remote.
7. Open a **draft** PR with `gh`.
8. Concurrently, using sub-agents:
   1. Verify the final PR body, title, base, and head.
   2. Load and follow the [`verify`](../verify/SKILL.md) skill.
      If verification fails, provide the parent agent with a report so
      that it can address the issues.
   3. Perform an [adversarial PR review](../adversarial-review/SKILL.md).
9. Present the adversarial review findings to the user. Do not address or
   dismiss any finding until the user has reviewed it and provided explicit
   direction.
10. Iterate on the outcomes of the previous steps according to the user's
    direction until verification succeeds, the findings have been addressed or
    dismissed, and any resulting changes have been pushed and passed the
    verification and metadata checks in step 8. The updated PR must also pass
    another adversarial review unless the changes since the previous review are
    purely mechanical and do not change behavior or meaning.
11. Monitor the CI run triggered by the previous push.
    It must succeed. If not, failures must be triaged and addressed.
12. Mark the PR as "ready to review".

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

## Output

Report the PR URL.
