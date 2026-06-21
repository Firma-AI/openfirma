---
name: split-jj-changeset
description: Split a jj changeset into smaller focused changesets without interactive commands. Use only in clones that use Jujutsu.
---

# Split a jj Changeset

Split the changeset `$ARGUMENTS` into smaller, focused units.

If `$ARGUMENTS` is empty, ask the user which revset to split.

## Core safety principle

Never edit the original changeset directly. Duplicate first:

```bash
jj duplicate <revset>
```

Only abandon the original after the split is verified.

## Workflow

1. Inspect the changeset.
2. Plan the grouping and validation with the user.
3. Duplicate the original.
4. Split by file path or reconstruct partial files for mixed hunks.
5. Set descriptions.
6. Verify completeness and correctness.
7. Rebase dependents if needed.
8. Clean up the original.

## Inspect the changeset

```bash
jj diff -r <revset> --stat
jj diff -r <revset>
jj log -r <revset>
```

Summarize the logical groups before changing anything.

## Plan with the user

Before proceeding, confirm:

- how to group the changes
- what description each resulting changeset should have
- how to validate each changeset

For mixed hunks within a file, ask the user how those hunks should be assigned.

## Split strategies

### File-path split

When each file belongs to one group:

```bash
jj split -r <rev> <paths...>
```

Repeat on the remainder until each group is isolated.

### Hunk-level split

When one file contains multiple logical groups:

1. Create empty changesets off the parent.
2. Restore whole files from the duplicate where possible.
3. Reconstruct partial files by applying only the intended hunks.
4. Write the resulting file content into the appropriate changeset.

Do not use `jj split -i`.

## Verification

### Completeness

```bash
jj interdiff --from <original-revset> --to <last-split-revset>
```

The combined split should match the original.

### Correctness

Run the validation plan agreed with the user. It is usually enough to run:

```bash
just check
```

Use narrower crate-level commands when appropriate during iteration.

## Cleanup

After verification, ask whether to abandon the original duplicate source:

```bash
jj abandon <original-revset>
```

## Rules

- Never use interactive jj commands.
- Never pass `--ignore-immutable` to a jj command.
- Duplicate first.
- Ask the user before choosing logical groupings.
- Verify both completeness and correctness before cleaning up.
