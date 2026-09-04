---
name: verify
description: Final verification for OpenFirma changes, including per-commit or per-changeset validation when work is split into atomic revisions.
---

# Verify Skill

Run comprehensive verification before finalizing changes.

## Usage

Use this skill before opening a PR, handing work back to a reviewer, or
finalizing a stack of commits or changesets.

## Instructions

Run the repository's full local verification target:

```bash
just check
```

Ensure the new code adheres to the policies defined in [`rust-tests-guidelines`](../rust-tests-guidelines/SKILL.md) and [`rust-docs-guidelines`](../rust-docs-guidelines/SKILL.md).

When preparing commits or jj changesets, verify each atomic unit when feasible,
not only the final combined state.

This commonly pairs with
[`commit-guidelines`](../commit-guidelines/SKILL.md)
when the work was split into checkpoint commits or changesets.

- Prefer `just check` for each commit or changeset.
- If `just check` is too expensive during iteration, run the narrowest relevant
  verification and state what was not run.
- Do not treat a stacked branch or dirty working copy as sufficient proof that
  each individual revision is mergeable.

## Formal-plan lifecycle verification

When [`planning-changes`](../planning-changes/SKILL.md) routed the PR to Full or
Compact mode, verify its history after implementation review and after the
mechanical plan removal. Resolve its recorded ownership base, accepted plan
commit, latest reviewed plan revision, current GitHub base, reviewed
implementation tip, and final tip first. For a stack, repeat these checks for
each PR's ownership range and collect ancestor plan paths separately.

Before removal, verify the ownership relationship, first-commit add and
contents, immutable locator, and that the plan is still present in the reviewed
tip. After removal, run every assertion below against the new final tip.

The evidence must establish all of these facts:

- the accepted plan commit is the direct child of the recorded ownership base
  and adds exactly the complete accepted plan Markdown, including its
  plan-review disposition log;
- the original accepted and latest reviewed commit SHAs use the one stable path
  and match their separate locators in the PR body;
- the reviewed pre-removal tip contains the same plan content as the latest
  reviewed same-path plan locator;
- the final commit deletes exactly that path and changes nothing else;
- the final commit is the immediate child of the reviewed tip;
- the path is absent from the final tip, immutable ownership-base diff, and
  current GitHub PR diff; and
- excluding the path, the closing commit leaves the effective implementation
  diff unchanged.

For Git, run the exact-path assertions below. Set every variable from immutable
plan, review, and PR metadata, not mutable local branch names.

```bash
ownership_base=<full-recorded-ownership-base-sha>
current_base=<full-current-github-base-sha>
plan_commit=<full-accepted-plan-commit-sha>
latest_plan_commit=<full-latest-reviewed-plan-commit-sha>
reviewed_tip=<full-pre-removal-reviewed-tip-sha>
tip=<full-pr-tip-sha>
plan_path=<stable-repository-relative-plan-path>

test "$(git rev-list --parents -n 1 "$plan_commit" | wc -w)" -eq 2
test "$(git rev-parse "$plan_commit^")" = "$ownership_base"
git merge-base --is-ancestor "$plan_commit" "$tip"
test "$(git rev-list --parents -n 1 "$latest_plan_commit" | wc -w)" -eq 2
git merge-base --is-ancestor "$plan_commit" "$latest_plan_commit"
git merge-base --is-ancestor "$latest_plan_commit" "$reviewed_tip"
git merge-base --is-ancestor "$reviewed_tip" "$tip"
test "$(git diff --name-status "$plan_commit^" "$plan_commit")" = "$(printf 'A\t%s' "$plan_path")"
git show "$plan_commit:$plan_path" >/dev/null
test "$(git diff --name-only "$latest_plan_commit^" "$latest_plan_commit")" = "$plan_path"
test "$(git rev-parse "$reviewed_tip:$plan_path")" = "$(git rev-parse "$latest_plan_commit:$plan_path")"
test "$(git rev-parse "$tip^")" = "$reviewed_tip"
test "$(git diff --name-status "$tip^" "$tip")" = "$(printf 'D\t%s' "$plan_path")"
if git cat-file -e "$tip:$plan_path" 2>/dev/null; then exit 1; fi
test -z "$(git diff --name-only "$ownership_base" "$tip" -- "$plan_path")"
current_merge_base=$(git merge-base "$current_base" "$tip")
test -z "$(git diff --name-only "$current_merge_base" "$tip" -- "$plan_path")"

owned_reviewed_patch=$(mktemp)
owned_final_patch=$(mktemp)
current_reviewed_patch=$(mktemp)
current_final_patch=$(mktemp)
trap 'rm -f "$owned_reviewed_patch" "$owned_final_patch" "$current_reviewed_patch" "$current_final_patch"' EXIT

git diff --binary "$ownership_base" "$reviewed_tip" -- . ":(exclude)$plan_path" > "$owned_reviewed_patch"
git diff --binary "$ownership_base" "$tip" -- . ":(exclude)$plan_path" > "$owned_final_patch"
git diff --binary "$current_merge_base" "$reviewed_tip" -- . ":(exclude)$plan_path" > "$current_reviewed_patch"
git diff --binary "$current_merge_base" "$tip" -- . ":(exclude)$plan_path" > "$current_final_patch"

cmp "$owned_reviewed_patch" "$owned_final_patch"
cmp "$current_reviewed_patch" "$current_final_patch"
```

Inspect the plan commit's diff content, not only its path status, to confirm the
accepted plan and complete dispositions. The lifecycle permits exactly one
stable PR-owned plan path, so any rename, split, or second plan path fails
review. For a stacked PR, run the final-tip and current-PR-diff absence checks
for every ancestor plan path as well as the current PR's path.

In a Jujutsu workspace, use `jj` to resolve and inspect the same revisions,
then use the emitted full Git commit IDs for the immutable GitHub locator and
object-level assertions above:

```bash
jj log -r '<ownership-base>..<tip>' --no-graph --reversed -T 'commit_id ++ "\n"'
jj diff -r <first-plan-revision> --summary
jj diff -r <closing-deletion-revision> --summary
```

The recorded ownership base and accepted first commit ID must remain unchanged
across base integration or restacking. If either changed after implementation
began, verification fails even when the plan contents are identical. If a clean
current-base range cannot preserve them, require a replacement PR and new plan
review.

Before finalizing, confirm that any required docs updates are present:

- docs under `docs-site/`
- `docs-site/public/llms.txt` when discovery or integration guidance changed

## Notes

- Do not mark work complete based only on a successful build; run the matching tests too.
- Required-check failures are blocking and must be traced to an actionable
  cause. Report coverage deltas separately; coverage pressure is not a
  correctness failure unless an enforced threshold or required check fails.
