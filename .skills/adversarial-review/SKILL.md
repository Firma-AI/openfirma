---
name: adversarial-review
description: Review changes ahead of opening a new PR, modifying an existing one or on demand by the user.
---

# Adversarial Review

Use this skill to decide who should review changes and how review work may be
delegated without duplication. The [`reviewing-changes`](../reviewing-changes/SKILL.md)
skill defines what every review must cover and how findings must be reported.

## Workflow

Every reviewer must load and follow the
[`reviewing-changes`](../reviewing-changes/SKILL.md) skill. When the current
agent reviews directly, load it in the current session. When a fresh reviewer
is required, instruct that reviewer to load it.

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

Present the reviewer's findings to the user without silently dismissing or
fixing them. If behavior-changing fixes are made after the review, obtain
another independent review. A repeat review may be skipped when subsequent
changes are purely mechanical and cannot affect behavior or meaning.

### Independent review task

Use this mode when the current agent did not participate in the implementation,
even if it also has verification, metadata, or other responsibilities. The
current agent is already the independent reviewer. It should perform the review
directly and must not launch another agent merely to repeat the same review.

The current agent may delegate a narrowly bounded, materially distinct part of
the review surface when that improves coverage or enables parallel
investigation. Examples include:

- validating one platform-specific code path;
- experimentally testing a specific exploit hypothesis;
- auditing one protocol or trust boundary;
- checking concurrency behavior separately from API compatibility; or
- inspecting a dependency or external implementation.

Such delegation is ordinary review decomposition, not an additional adversarial
review. Each delegated task must have explicit boundaries and must not repeat
the complete end-to-end review. Limited overlap is expected when the current
agent integrates and validates delegated findings. The current agent remains
responsible for resolving contradictions, removing duplicates, and producing
the final review.

## Output

Follow the report requirements in the
[`reviewing-changes`](../reviewing-changes/SKILL.md) skill. When the current
agent is implementation-involved, present the independent review findings to
the user without addressing or dismissing them until the user provides explicit
direction.
