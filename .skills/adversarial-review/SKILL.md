---
name: adversarial-review
description: Review changes ahead of opening a new PR, modifying an existing one or on demand by the user.
---

## Workflow

To perform an adversarial review:

- launch a fresh sub-agent session;
- give the reviewer only the PR URL (if a PR exists) or the final revision
- do not preload the reviewer with implementation history, local rationale, or
  how the change was constructed
- ask it to review like an independent reviewer and prioritize bugs,
  regressions, type safety, breaking changes, risky assumptions, and missing tests

The goal is to simulate a skeptical reviewer who only sees the PR, not the
authoring process behind it.

The initial adversarial review is required. An additional review round may be
skipped when changes made after the previous review are purely mechanical and
do not change behavior or meaning, such as formatting or lint fixes.

## Output

A report with findings, sorted by severity/urgency.

Present the report to the user. Do not address or dismiss any finding until the
user has reviewed it and provided explicit direction.
