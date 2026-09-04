---
name: edit-pr
description: Edit a pre-existing GitHub pull request for OpenFirma. Use whenever you are asked to make changes to commits, branches or bookmarks that would affect an open GitHub PR.
---

# Edit PR

Use this workflow whenever you are asked to make changes to commits, branches or bookmarks
that would affect an open GitHub pull request for OpenFirma.

## Terminology

A PR is defined as **protected** if a user that's clearly not a bot has submitted a review or
left a review or issue comment on it.

## Initial analysis

1. Inspect the repository state and active VCS.
2. Determine the impacted PRs:
   1. If working with `git`, use branch names to find corresponding PRs.
   2. If working with `jj`, use bookmark names to find corresponding PRs.
3. For each impacted PR, determine if it's **protected** or not.
4. For each impacted PR, read its **Design Plan** evidence and determine whether
   formal planning applied, whether implementation has begun, and whether its
   closing plan deletion already occurred.

If the PR is protected, see [#protected-pr-workflow].
Otherwise, follow [#non-protected-pr-workflow].

## Plan lifecycle constraints

Follow the canonical lifecycle in
[`planning-changes`](../planning-changes/SKILL.md). While plan review is
unresolved and implementation has not started, the first plan commit may be
replaced at the same stable path and reviewed again. After implementation
starts, its ownership base, full commit SHA, and plan path must not change, even
when the PR is otherwise non-protected.

Treat a closing plan deletion as a closure boundary: do not append meaningful
changes after it. For a non-protected PR, move or drop the old deletion before
new work, keep the plan available through another implementation review, and
create a new final deletion-only commit. For a protected PR whose history
cannot be rewritten, restore the stable plan path from the latest reviewed plan
revision's commit-pinned locator in one mechanical commit before new work, then
delete it again in a new final mechanical commit after review and finding
disposition. Preserve the original accepted-plan locator as provenance and
record the latest reviewed plan locator separately as the source of the current
plan.

For a stacked PR, update the base without rewriting accepted plan commits and
verify against the immutable ownership base and current GitHub diff. If a clean
current-base range would require rewriting accepted ownership history, create a
replacement PR and replan. Verify that no ancestor plan path reappears in any
descendant tip.

## Protected PR workflow

You are allowed to rewrite the history of protected PR **if and only if** you are rebasing on top of the latest changes to the target branch and all your changes to the existing revisions are geared towards resolving the conflict that arose from the rebase.
This permission never extends to an accepted plan commit after implementation
has begun; preserve that commit and use the base-integration rules above.

If that's not the case, all new changes should be packaged as _new revisions_ on top of
the existing ones.
Load and follow the [`commit-guidelines`](../commit-guidelines/SKILL.md) skill when doing so.

After you're done with your changes, follow the [#push-workflow].

## Non-protected PR workflow

If a PR is not protected, you are free to change its history as you see fit,
except for an accepted plan commit after implementation has begun. Follow the
[#push-workflow].

## Push Workflow

Once the changes you want to push are ready, follow this checklist:

1. Load and follow the [`verify`](../verify/SKILL.md) skill.
   Verification must succeed before you move forward. For planned work, run
   the pre-removal checks here and reserve the final lifecycle assertions for
   step 6.
2. Push the new changes.
3. Perform an [adversarial review](../adversarial-review/SKILL.md).
4. Present the adversarial review findings to the user. Do not address or
   dismiss any finding until the user has reviewed it and provided explicit
   direction.
5. Iterate on the outcomes of the previous step according to the user's
   direction, until:
   1. Verification succeeds.
   2. Findings from the adversarial review have been addressed/dismissed.
   3. Any resulting changes have been pushed.
   4. The updated PR has passed another adversarial review, unless the changes
      since the previous review are purely mechanical and do not change
      behavior or meaning.
6. When formal planning applied, create and push the final plan deletion-only
   commit after the review and dispositions above, run the lifecycle checks in
   [`verify`](../verify/SKILL.md), and record the closing commit SHA in the PR
   body. Do not repeat adversarial review for this mechanical deletion.
7. Verify the affected PR body, title, base, and head.
   1. Update the PR body and/or title with `gh` if the new changes
      have made the existing one outdated.
8. Spin up a background job to monitor to the CI run triggered by the latest push.
   It must succeed. If not, failures must be triaged and addressed.

## Output

Report the PR URL.
