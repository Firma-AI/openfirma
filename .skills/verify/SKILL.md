---
name: verify
description: Run final verification before handing off OpenFirma changes or creating a PR.
---

# Verify Skill

Run comprehensive verification before finalizing changes.

## Usage

Use this skill before opening a PR or handing work back to a reviewer.

## Instructions

Run the repository's full local verification target:

```bash
just check
```

Ensure the new code adheres to the policies defined in [`rust-tests-guidelines`](../rust-tests-guidlines/SKILL.md) and [`rust-docs-guidelines`](../rust-docs-guidelines/SKILL.md).

Before finalizing, confirm that any required docs updates are present:

- docs under `docs-site/`
- `docs-site/public/llms.txt` when discovery or integration guidance changed

## Notes

- Do not mark work complete based only on a successful build; run the matching tests too.
