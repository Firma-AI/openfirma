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

If the PR is protected, see [#protected-pr-workflow].
Otherwise, follow [#non-protected-pr-workflow].

## Protected PR workflow

You are allowed to rewrite the history of protected PR **if and only if** you are rebasing on top of the latest changes to the target branch and all your changes to the existing revisions are geared towards resolving the conflict that arose from the rebase.

If that's not the case, all new changes should be packaged as _new revisions_ on top of
the existing ones.
Load and follow the [`commit-guidelines`](../commit-guidelines/SKILL.md) skill when doing so.

After you're done with your changes, follow the [#push-workflow].

## Non-protected PR workflow

If a PR is not protected, you are free to change its history as you see fit.
Follow the [#push-workflow].

## Push Workflow

Once the changes you want to push are ready, follow this checklist:

1. Load and follow the [`verify`](../verify/SKILL.md) skill.
   Verification must succeed before you move forward.
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
6. Verify the affected PR body, title, base, and head.
   1. Update the PR body and/or title with `gh` if the new changes
      have made the existing one outdated.
7. Spin up a background job to monitor to the CI run triggered by the latest push.
   It must succeed. If not, failures must be triaged and addressed.

## Output

Report the PR URL.
