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

Before finalizing, confirm that any required docs updates are present:

- docs under `docs-site/`
- `docs-site/public/llms.txt` when discovery or integration guidance changed

## Notes

- Do not mark work complete based only on a successful build; run the matching tests too.
- Required-check failures are blocking and must be traced to an actionable
  cause. Report coverage deltas separately; coverage pressure is not a
  correctness failure unless an enforced threshold or required check fails.
