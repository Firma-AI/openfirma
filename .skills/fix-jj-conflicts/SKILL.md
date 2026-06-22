---
name: fix-jj-conflicts
description: Fix merge conflicts in a jj change and its ancestors, starting from the oldest conflict. Use only in clones that use Jujutsu.
---

# Fix jj Conflicts

Resolve all conflicts in a set of jj changes, starting from the oldest, then verify the result.

If `$ARGUMENTS` is empty, default to `-b @`.

## Input modes

`$ARGUMENTS` accepts one of these forms:

- `-s <rev>` or `--source <rev>`: the revision and all descendants
- `-b <rev>` or `--branch <rev>`: the whole branch
- `-r <revs>` or `--revisions <revs>`: only the specified revisions

If no flag is provided, treat the argument as `-s <rev>`.

## Instructions

### 1. Identify conflicted changes

```bash
jj log -r '(<target-revset>) & conflicts()'
```

Process conflicts from oldest to newest. In jj log output, the oldest change is closest to the bottom.

If no conflicts are found, report that and stop.

### 2. Resolve conflicts bottom-up

For each conflicted change:

```bash
jj log -r <conflicted-change>
jj diff -r <conflicted-change>
jj new -A <conflicted-change>
```

Resolve the files, remove all conflict markers, and describe the fix:

```bash
jj describe -m "CONFLICT FIX: <short description>"
```

If unsure about the correct resolution, ask the user rather than guessing.

### 3. Verify after each fix

Run:

```bash
just check
```

### 4. Re-check remaining conflicts

After each fix:

```bash
jj log -r '(<target-revset>) & conflicts()'
```

Skip downstream conflicts that disappeared after the ancestor fix.

### 5. Final verification

After all conflicts are resolved, confirm no conflicts remain and verify the final state:

```bash
jj log -r '(<target-revset>) & conflicts()'
just check
```

### 6. Cleanup

Ask the user whether to squash fix changes into their parents:

```bash
jj squash --from <fix-change> --into <conflicted-change> -u
```

## Rules

- Never use interactive commands.
- Never pass `--ignore-immutable` to a jj command.
- Always process oldest conflicts first.
- Always verify after resolving a conflict.
- Ask the user when intent is ambiguous.
