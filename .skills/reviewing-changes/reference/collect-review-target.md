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
git ls-files --others --exclude-standard

# Jujutsu: current working-copy change.
jj status
jj diff -r @ --git
```

`git ls-files` only lists untracked paths. Open every listed file in full with a
reader appropriate to its type; do not treat the listing as review coverage.

## Path scope

Apply the requested paths to both the diff and full-file inspection. Preserve
the same base/head or working-tree scope used by the containing review.

```bash
# Git working tree, including untracked paths in scope.
git status --short -- <paths...>
git diff HEAD -- <paths...>
git ls-files --others --exclude-standard -- <paths...>

# Git revision or range.
git show <commit> -- <paths...>
git diff <base>...<head> -- <paths...>

# Jujutsu working copy or revision.
jj status -- <filesets...>
jj diff -r @ --git -- <filesets...>
jj diff -r <revision> --git -- <filesets...>
jj diff --from <base> --to <head> --git -- <filesets...>
```

After collecting the diff, enumerate its added and modified paths and read each
file in full. For Git, use `git diff --name-status` with the same revision and
path arguments; for Jujutsu, add `--name-only` to the same `jj diff` command.

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

## Revision stacks

Record an immutable base immediately before the stack and its immutable tip.
Review revisions oldest first, then review the cumulative endpoint diff.

```bash
# Git: enumerate the ancestry path, inspect each commit, then the cumulative
# base-to-tip result.
git rev-list --ancestry-path --reverse <base>..<tip>
git show <commit-from-list>
git diff <base> <tip>

# Jujutsu: enumerate oldest first, inspect each changeset, then the cumulative
# base-to-tip result.
jj log -r '<base>..<tip>' --no-graph --reversed
jj diff -r <revision-from-list> --git
jj diff --from <base> --to <tip> --git
```

Run the per-revision command for every listed revision. If the stack contains a
merge, inspect its parent relationships and each relevant parent diff rather
than assuming a linear predecessor. Apply the path arguments from the previous
section when the user requested a path-scoped stack review.

## GitHub pull request

Read the pull request's repository URL and immutable revision metadata. Fetch
from that base repository URL rather than assuming any configured remote points
to it, verify both objects, and compute the merge base used for the review
range:

```bash
metadata=$(gh pr view <number> --json url,baseRefName,baseRefOid,headRefOid)
pr_url=$(printf '%s' "$metadata" | jq -r .url)
base_repo_url=${pr_url%/pull/*}
base_ref=$(printf '%s' "$metadata" | jq -r .baseRefName)
base_oid=$(printf '%s' "$metadata" | jq -r .baseRefOid)
head_oid=$(printf '%s' "$metadata" | jq -r .headRefOid)

git fetch "$base_repo_url.git" "$base_ref" "refs/pull/<number>/head"
git cat-file -e "$base_oid^{commit}"
git cat-file -e "$head_oid^{commit}"
merge_base=$(git merge-base "$base_oid" "$head_oid")
git diff "$merge_base" "$head_oid"
```

In a Jujutsu workspace, use Git to materialize GitHub's pull-request ref, then
import and review the same immutable endpoints:

```bash
jj git import
jj diff --from "$merge_base" --to "$head_oid" --git
```

Record the base repository URL and all three revision IDs. If the pull request
changes while the review is in progress, finish against the recorded head or
restart explicitly; do not silently mix revisions. Add `-- <paths...>` to the
Git diff or `-- <filesets...>` to the Jujutsu diff for an explicitly path-scoped
PR review, and still inspect every added or modified file in that scope.
