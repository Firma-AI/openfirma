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

Run the read-only inspector from the repository root:

```bash
uv run .skills/edit-pr/scripts/inspect_prs.py
```

The script probes `jj` before falling back to Git, finds open PRs whose head
matches the active branch or nearest ancestor bookmarks, and classifies each PR
as `protected`, `unprotected`, or `indeterminate`. It emits the evidence as
JSON. If the result is `indeterminate`, ask the user instead of treating the PR
as unprotected.

Use `--repo OWNER/REPO`, `--head-owner OWNER`, or one or more `--ref NAME`
arguments when automatic detection is not appropriate. Empty discovery and a
branch name shared by multiple fork owners return `manual_required` rather than
assuming the PR is unprotected. Determining whether the revision contains mixed
intents remains a manual review step.

## Stacked PRs

When PRs target one another, inspect the complete linear stack after local
changes but before pushing:

```bash
uv run .skills/edit-pr/scripts/inspect_stack.py \
  --repo OWNER/REPO \
  --tip-ref <any-stack-head> \
  --manifest <manifest.json>
```

The script follows GitHub `baseRefName -> headRefName` edges down to `main` and
up to the stack tip. It compares each published PR's aggregate immediate-base-
to-tip diff with the candidate local bookmark range. A changed commit ID alone
does not make a descendant PR content-impacted.

- An exact unchanged diff is a mechanical rewrite for a protected PR only when
  its base also changed as part of the rebase. Other protected history rewrites
  return `manual_required`.
- A changed diff on an unprotected PR is allowed.
- A changed diff on a protected PR returns `manual_required`. Inspect the old
  and candidate ranges and decide whether the difference is only required for
  the rebase or materially changes that PR.
- An ambiguous, nonlinear, branched, or unavailable stack returns
  `manual_required`.
- A changed candidate base without a corresponding head rewrite returns
  `manual_required`; checks attached to the unchanged head SHA are stale for the
  new PR range.

Keep the manifest until the pushed stack has passed verification and CI. It is
the immutable record of the published and candidate SHAs and diff fingerprints.
The script writes that complete record to `--manifest` and prints only a compact
PR decision summary to stdout to avoid loading commit and review detail into the
agent context.
Post-push verification also requires every recorded PR to remain open and
unmerged and the owner's complete open stack graph to remain unchanged.
The script assumes stack heads are pushed to the upstream repository owner and
that their jj remote is `origin`. Use `--head-owner` and `--remote` to override
those independently.

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
6. Verify the affected PR body, title, base, head, draft state, and exact commit
   sequence with the read-only script:

   ```bash
   uv run .skills/open-pr/scripts/verify_pr.py \
     --pr <url> \
     --expected-base <base> \
     --expected-head-owner <owner> \
     --expected-head-ref <ref> \
     --expected-head-sha <sha> \
     --expected-title <title> \
     --expected-draft <true-or-false> \
     --expected-commit <sha>
   ```

   1. Update the PR body and/or title with `gh` if the new changes
      have made the existing one outdated.
   2. For a stack, verify all pushed base/head edges and per-PR commit ranges:

      ```bash
      uv run .skills/open-pr/scripts/verify_stack.py \
        --manifest <manifest.json>
      ```
7. Wait for CI on the exact pushed head:

   ```bash
   uv run .skills/open-pr/scripts/wait_ci.py \
     --pr <url> \
     --expected-head-sha <sha> \
     --expected-check <required-check-name>
   ```

   Repeat `--expected-check` for every required check. CI must succeed. If
   `codecov/patch` returns `manual_required`, inspect the coverage change and
   affected code, then record why the signal is acceptable or requires more
   tests. All other failures must be triaged and addressed.

   For a stack, monitor every rewritten PR concurrently using the same manifest:

   ```bash
   uv run .skills/open-pr/scripts/wait_stack_ci.py \
     --manifest <manifest.json> \
     --expected-check <required-check-name>
   ```

   If inspection returned `manual_required` and the model recorded an allowed
   protected rebase-only diff interpretation, pass `--allow-manual` explicitly
   to both stack consumers. Structural failures, nonlinear stacks, unknown
   protection, and base changes without head rewrites cannot be overridden.
   Stack CI pins both base and head SHAs and re-verifies the complete open graph
   before and after waiting.

## Output

Report the PR URL.
