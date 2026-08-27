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
6. Record the `planning-changes` routing in the required **Design Plan** PR-body
   section. For Full or Compact work, confirm that the first PR-owned commit is
   the complete accepted plan-only commit relative to the recorded ownership
   base, and link both the original accepted and latest reviewed plan revisions
   at the stable path. For an exemption, record `Not applicable` and the
   exemption rationale without creating a plan artifact.
7. Push the review head to the correct remote.
8. Open a **draft** PR with `gh`.
9. Concurrently, using sub-agents:
   1. Verify the final PR body, title, base, and head.
   2. Load and follow the [`verify`](../verify/SKILL.md) skill.
      For planned work, run the pre-removal checks now and reserve the final
      lifecycle assertions for step 12. If verification fails, provide the
      parent agent with a report so that it can address the issues.
   3. Perform an [adversarial PR review](../adversarial-review/SKILL.md).
10. Present the adversarial review findings to the user. Do not address or
    dismiss any finding until the user has reviewed it and provided explicit
    direction.
11. Iterate on the outcomes of the previous steps according to the user's
    direction until verification succeeds, the findings have been addressed or
    dismissed, and any resulting changes have been pushed and passed the
    verification and metadata checks in step 9. The updated PR must also pass
    another adversarial review unless the changes since the previous review are
    purely mechanical and do not change behavior or meaning.
12. For Full or Compact work, only after step 11 is complete, create and push
    the final deletion-only commit from the plan lifecycle in
    [`planning-changes`](../planning-changes/SKILL.md). Run the lifecycle checks
    in [`verify`](../verify/SKILL.md), then update the PR body with the full
    closing commit SHA and verification result. Do not run another adversarial
    review for this mechanical deletion.
13. Monitor the CI run triggered by the previous push.
    It must succeed. If not, failures must be triaged and addressed.
14. Mark the PR as "ready to review".

For `jj` repositories, create or update a bookmark that points at the intended
review tip before pushing it to the selected remote.

## Verify after creation

After creating the PR, inspect it with `gh pr view` and confirm:

- title matches repo style
- base branch is correct
- head branch or bookmark is correct
- body follows the PR template
- all intended commits are included
- the Design Plan section records either a justified exemption or the immutable
  ownership base, accepted-plan locator, and, before ready-for-review, its
  closing removal SHA
- for planned work, the final tip passes the formal-plan lifecycle verification

If the body does not match what you requested, fix it immediately instead of
assuming the create or edit step worked.

## Output

Report the PR URL.
