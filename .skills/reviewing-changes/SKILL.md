---
name: reviewing-changes
description: Defines the baseline scope and reporting requirements for code and documentation reviews. Use when reviewing a pull request, revision, diff, or working-tree change.
---

# Reviewing Changes

Use these guidelines for every review, whether the reviewer works directly or
as an independent reviewer delegated by another agent.

## Establish the review target

Resolve the exact working tree, path set, revision range, stack, or pull request
base and head before loading specialized guidance. Use
[`collect-review-target`](reference/collect-review-target.md) when command-level
Git or Jujutsu instructions are needed. Pass the resolved scope to specialized
guidance; language-specific skills do not reacquire or redefine it.

## Review Scope

Inspect the complete change and read enough surrounding code or documentation
to understand the affected contracts. Review the intended behavior first, then
whether the implementation preserves it.

When the planning workflow applied, read the accepted plan and disposition log
from the original accepted full commit-SHA-and-path locator and the latest
reviewed locator at that same stable path. Preserve the original accepted
locator as provenance when a later reviewed plan revision exists. Separately
validate that the recorded ownership base is the original plan commit's parent;
the ownership base does not contain the plan. Never rely on a plan path at
`HEAD`: the plan is removed mechanically after this review. Treat the plan as
intent and historical context, not as proof or maintained documentation.

Prioritize actionable issues involving:

- correctness bugs and behavior regressions;
- security and trust-boundary weaknesses;
- type-safety problems;
- breaking API, configuration, wire-format, or operational changes;
- risky assumptions and unsupported edge cases;
- missing or ineffective tests for changed behavior; and
- documentation that would mislead users or contributors.

For security or material hardening recommendations, establish the actors,
authority and trust boundaries, supported workloads and deployment modes,
attacker capability, and protected asset. Show that the suspect state is
reachable in that model before adding defenses, and prefer repairing the
invariant at its owner over adding downstream guards.

Judge guardrails against their stated misuse model. An accident-prevention
check need not resist deliberate bypass unless it is claimed as a security
boundary. Do not preserve compatibility when doing so keeps a confirmed
security bypass viable; identify the break and migration explicitly.

When reviewing a stack, inspect both each revision and the cumulative tip.
Label findings that exist only in an intermediate revision; report a surviving
defect only when it remains in the cumulative result.

Apply any more specific repository or language review guidance in addition to
this baseline. Before reviewing, identify the languages and file types in the
change and load the specialized guidance that applies to each subset:

- For Rust source or test changes, load and follow
  [`review-rust-code`](../review-rust-code/SKILL.md).

Apply specialized guidance only to its matching subset of the change. Loading a
specialized skill does not delegate that review work or require another agent.
Honor review priorities explicitly requested by the user.

## Report

Return one severity-ordered report. For each finding, include:

- concrete file and line evidence;
- the trigger conditions and causal chain from the changed code to the
  observable behavior;
- the practical or operational impact;
- a suggested correction when one is reasonably clear; and
- relevant unverified assumptions.

A recommendation for a material abstraction must identify its owner and
consumers, operational role, construction or update lifecycle, relevant costs,
and what it replaces or deliberately does not solve.

When the user requests a saved or shareable review artifact, make it stand
without thread context. State the reviewed scope, intended behavior,
verification limits, and assumptions, and include any supporting code needed
to use a requested self-contained snippet.

Report only actionable findings. Do not include process narration or duplicate
findings from multiple reviewers. If there are no findings, say so plainly and
note any residual risk or untested areas.
