---
name: commit-guidelines
description: Dirty repo, uncommitted changes, commit, amend, split, changeset, PR history: inspect repository state and prepare atomic Git commits or jj changesets. Use whenever the worktree is already dirty or you are about to commit or rewrite history.
---

# Commit Guidelines

Use this workflow whenever the worktree is already dirty or you are about to
commit, split, amend, squash, or otherwise touch revision history.

Prefer local checkpoint commits or jj changesets during substantial work.

- Use them to preserve progress before risky edits, broad refactors, or context
  switches.
- Keep each checkpoint atomic: one clear intent, with matching tests, docs, or
  config when they are required for that intent.
- Prefer checkpoints that can pass `just check` on their own. If that is too
  expensive or not yet possible, run the narrowest relevant verification and
  state what remains.
- If work is already under review in an open PR, preserve that history by
  default and add follow-up revisions instead of rewriting reviewed ones.

## Workflow

1. Inspect the repository state before changing anything else.
2. Decide whether existing uncommitted changes and the new task belong in the
   same revision.
3. Decide whether the target branch or changeset is already under review.
4. If either relationship is unclear, ask the user before mixing work or
   rewriting history.
5. Isolate one logical group.
6. Verify that group.
7. Create the commit or changeset.
8. Report what was committed and what verification ran.

## Inspect the starting state

Use the repository's active VCS.

```bash
# Git
git status --short
git diff
git diff --cached
git log --oneline -10

# jj
jj status
jj diff
jj log
```

Do this whenever you inherit a dirty working copy, not only immediately before
creating a commit.

If the repository already has uncommitted changes, decide whether the new work:

- extends the same in-progress intent and should stay together
- is unrelated and should go into a separate commit or changeset

If that relationship is unclear, ask the user before mixing work.

Also decide whether the target branch or changeset is already under review.

- If yes, prefer follow-up revisions that preserve the reviewed history.
- Rewrite reviewed history only when the user explicitly asks.

## Grouping rules

Group by intent, not by file type.

- Keep tests, docs, and config in the same revision when they are required to
  make the intent correct, verifiable, or understandable.
- Do not mix unrelated cleanup, formatting, refactors, and behavior changes.
- If a file contains mixed logical changes and the split is ambiguous, ask the
  user before assigning those hunks.

## Git workflow

1. Stage only the intended files or hunks.
2. Inspect the staged result.
3. Run verification.
4. Commit with a concise message describing the single intent.

```bash
git add <paths...>
git diff --cached
just check
git commit -m "<intent>"
```

If `just check` is too expensive during iteration, run the narrowest relevant
verification first, but report what remains unverified.

For unreviewed local work, it is fine to reshape local Git history to keep it
atomic. For branches with an open PR or active review, prefer follow-up commits
over amend, rebase, or force-push.

## Jujutsu workflow

1. Ensure the target changeset contains only one intent.
2. If it mixes multiple intents, split it before describing it.
3. Verify the resulting changeset.
4. Set a concise description describing the single intent.

```bash
jj diff -r <revset>
jj split -r <rev> <paths...>
just check
jj describe -r <rev> -m "<intent>"
```

For mixed hunks within one file, reconstruct the file content deliberately.

For unreviewed local work, it is fine to reshape the jj stack to keep it
atomic. For changesets already under review, avoid rewriting them unless the
user explicitly asks.

## Output

Report:

- the revision you created or updated
- the intent it represents
- whether the repository had pre-existing changes
- whether those changes were kept together or separated
- what verification ran
