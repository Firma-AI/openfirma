# Collect a Review Target

Use this reference when a review target has not already been resolved to an
exact working tree, path set, revision range, stack, or pull request base and
head. Follow the repository's active-VCS rules in `AGENTS.md`.

## Principles

- Record the resolved base, head, paths, and whether the target is a stack.
- Inspect untracked files separately; ordinary diffs do not include them.
- For a stack, review each revision and the cumulative base-to-tip diff.
- For a pull request, use its actual base and head metadata. Do not assume the
  target branch is `main`, and do not substitute a mutable local tracking branch
  for the recorded revisions.
- Read the full contents of every added or modified file after collecting the
  diff.

## Working tree

```bash
# Git: staged and unstaged changes relative to HEAD, plus untracked paths.
git status --short
git diff HEAD

# Jujutsu: current working-copy change.
jj status
jj diff -r @ --git
```

## Git revisions

```bash
# One commit.
git show <commit>

# Explicit base and head.
git diff <base>...<head>
```

Use two-dot only when the requested scope is explicitly the endpoint tree diff
rather than changes since the merge base.

## Jujutsu revisions

```bash
# One changeset or revset selected by the user.
jj diff -r <revset> --git

# Explicit endpoint trees.
jj diff --from <base> --to <head> --git
```

## GitHub pull request

Read the pull request's immutable revision metadata, fetch its head and base
branch, and compute the merge base used for the review range:

```bash
metadata=$(gh pr view <number> --json baseRefName,baseRefOid,headRefOid)
base_ref=$(printf '%s' "$metadata" | jq -r .baseRefName)
base_oid=$(printf '%s' "$metadata" | jq -r .baseRefOid)
head_oid=$(printf '%s' "$metadata" | jq -r .headRefOid)

git fetch origin "$base_ref" "refs/pull/<number>/head"
merge_base=$(git merge-base "$base_oid" "$head_oid")
git diff "$merge_base" "$head_oid"
```

In a Jujutsu workspace, use Git to materialize GitHub's pull-request ref, then
import and review the same immutable endpoints:

```bash
jj git import
jj diff --from "$merge_base" --to "$head_oid" --git
```

Record all three revision IDs. If the pull request changes while the review is
in progress, finish against the recorded head or restart explicitly; do not
silently mix revisions.
