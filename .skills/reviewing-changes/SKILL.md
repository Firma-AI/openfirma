---
name: reviewing-changes
description: Defines the baseline scope and reporting requirements for code and documentation reviews. Use when reviewing a pull request, revision, diff, or working-tree change.
---

# Reviewing Changes

Use these guidelines for every review, whether the reviewer works directly or
as an independent reviewer delegated by another agent.

## Review Scope

Inspect the complete change and read enough surrounding code or documentation
to understand the affected contracts. Review the intended behavior first, then
whether the implementation preserves it.

Prioritize actionable issues involving:

- correctness bugs and behavior regressions;
- security and trust-boundary weaknesses;
- type-safety problems;
- breaking API, configuration, wire-format, or operational changes;
- risky assumptions and unsupported edge cases;
- missing or ineffective tests for changed behavior; and
- documentation that would mislead users or contributors.

Apply any more specific repository or language review guidance in addition to
this baseline. Honor review priorities explicitly requested by the user.

## Report

Return one severity-ordered report. For each finding, include:

- concrete file and line evidence;
- the conditions required to trigger the issue;
- the expected impact;
- a suggested correction when one is reasonably clear; and
- relevant unverified assumptions.

Report only actionable findings. Do not include process narration or duplicate
findings from multiple reviewers. If there are no findings, say so plainly and
note any residual risk or untested areas.
