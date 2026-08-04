---
name: adversarial-review
description: Review changes ahead of opening a new PR, modifying an existing one or on demand by the user.
---

# Adversarial Review

Use this skill to obtain an independent review of changes without duplicating
review work.

## Workflow

First determine whether the current agent participated in producing the
changes. The current agent is implementation-involved if it:

- wrote or edited the changes;
- directed or orchestrated their implementation;
- made design decisions that shaped the implementation; or
- is continuing in the same implementation context and therefore knows the
  author's rationale.

Merely reading the PR or beginning a review does not make the current agent
implementation-involved.

### Post-implementation adversarial review

Use this mode when the current agent is implementation-involved. The current
agent must launch a fresh reviewer because it cannot independently review its
own work. Give the reviewer:

- the PR URL, or the final revision when no PR exists;
- the intended externally observable behavior, if the PR does not state it
  clearly; and
- any review priorities explicitly requested by the user.

Do not give the reviewer:

- implementation history;
- author rationale not present in the change;
- the current agent's conclusions;
- explanations of why particular implementation choices were made; or
- suggested findings.

Ask the reviewer to independently inspect the complete change and prioritize
correctness bugs, security issues, regressions, breaking changes, risky
assumptions, and missing tests.

Present the reviewer's findings to the user without silently dismissing or
fixing them. If behavior-changing fixes are made after the review, obtain
another independent review. A repeat review may be skipped when subsequent
changes are purely mechanical and cannot affect behavior or meaning.

### Independent review task

Use this mode when reviewing is the current agent's only role and it did not
participate in the implementation. The current agent is already the independent
reviewer. It should perform the review directly and must not launch another
agent merely to repeat the same review.

The current agent may delegate a narrowly bounded, materially distinct part of
the review surface when that improves coverage or enables parallel
investigation. Examples include:

- validating one platform-specific code path;
- experimentally testing a specific exploit hypothesis;
- auditing one protocol or trust boundary;
- checking concurrency behavior separately from API compatibility; or
- inspecting a dependency or external implementation.

Such delegation is ordinary review decomposition, not an additional adversarial
review. Each delegated task must have explicit boundaries and must not duplicate
the current agent's broad review scope. The current agent remains responsible
for validating delegated findings, resolving contradictions, removing
duplicates, and producing the final review.

## Output

Return one severity-ordered report containing:

- findings with concrete file and line evidence;
- the conditions required to trigger each issue;
- the expected impact;
- relevant unverified assumptions; and
- a clear statement when no actionable findings were found.

Do not include process narration or duplicated findings from multiple
reviewers. When the current agent is implementation-involved, present the
independent review findings to the user without addressing or dismissing them
until the user provides explicit direction.
