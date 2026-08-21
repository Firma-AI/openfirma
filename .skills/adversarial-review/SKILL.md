---
name: adversarial-review
description: Selects an independent reviewer for OpenFirma design plans and implemented changes without duplicating review work. Use before implementation, before opening or modifying a PR, or when the user requests adversarial review.
---

# Adversarial Review

Use this skill to decide who should review a design plan or implemented change
and how review work may be delegated without duplication.

## Workflow

First classify the review target:

- For a pre-implementation design plan, load and follow
  [`reviewing-plans`](../reviewing-plans/SKILL.md).
- For a diff, revision, working tree, or pull request, load and follow
  [`reviewing-changes`](../reviewing-changes/SKILL.md) plus any specialized
  guidance it requires.

When the current agent reviews directly, load the applicable guidance in the
current session. When a fresh reviewer is required, instruct that reviewer to
load it.

Then determine whether the current agent participated in producing the review
target. The current agent is involved if it:

- wrote or edited the plan or changes;
- directed or orchestrated their design or implementation;
- made decisions that shaped the target; or
- is continuing in the same design or implementation context and therefore
  knows the author's rationale.

Merely reading the PR or beginning a review does not make the current agent
involved.

### Pre-implementation plan review

When the current agent is involved in producing the plan, launch a fresh
reviewer. Give it:

- the task and explicit user constraints;
- the candidate plan; and
- the repository revision the plan describes.

Do not give it hidden planner rationale, the current agent's conclusions, or
suggested findings. The reviewer must inspect the repository independently;
plan citations are leads rather than a closed review boundary.

Preserve the reviewer's original findings. The planner may append dispositions
under the rules in `reviewing-plans`, but must not silently erase or rewrite a
concern. Pre-implementation review does not replace independent review of the
implemented result.

### Post-implementation adversarial review

Use this mode when the current agent is involved in the implementation. The
current agent must launch a fresh reviewer because it cannot independently
review its own work. Give the reviewer:

- the PR URL, or the final revision when no PR exists;
- the intended externally observable behavior, if the PR does not state it
  clearly;
- the durable locator for the accepted design plan and its pre-review
  disposition log when the planning workflow applied; and
- any review priorities explicitly requested by the user.

Do not give the reviewer:

- implementation history;
- author rationale not present in the change;
- the current agent's conclusions;
- explanations of why particular implementation choices were made; or
- suggested findings.

The accepted plan is an intent and traceability input, not proof of
correctness. Independently reconstruct actual behavior and report plan
deviations, unmet proof obligations, newly reachable risks, and dispositions
that implementation evidence contradicts. When the planning workflow applied
but its artifact is missing or inaccessible, report the resulting conformance
and proof-obligation gap instead of silently treating the plan as absent.

Present the reviewer's findings to the user without silently dismissing or
fixing them. If behavior-changing fixes are made after the review, obtain
another independent review. A repeat review may be skipped when subsequent
changes are purely mechanical and cannot affect behavior or meaning.

### Independent review task

Use this mode when the current agent did not participate in producing the plan
or implementation, even if it also has verification, metadata, or other
responsibilities. The current agent is already the independent reviewer. It
should perform the review directly and must not launch another agent merely to
repeat the same review.

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

For plan reviews, follow the finding and disposition requirements in
[`reviewing-plans`](../reviewing-plans/SKILL.md). For implemented changes,
follow [`reviewing-changes`](../reviewing-changes/SKILL.md). When the current
agent is implementation-involved, present post-implementation findings to the
user without addressing or dismissing them until the user provides explicit
direction.
