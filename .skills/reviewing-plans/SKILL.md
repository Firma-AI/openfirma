---
name: reviewing-plans
description: Independently reviews an OpenFirma design plan before implementation by inspecting the repository, reconstructing high-risk traces, challenging proof obligations, and reporting preserved findings. Use for Full and Compact planning review.
---

# Reviewing Plans

Use this skill for independent pre-implementation review. Review the intended
outcome first, then whether the plan is supported by the repository and can be
implemented and verified without hidden design decisions.

## Independence

Reviewer selection, involvement classification, and handoff isolation are
preconditions owned by
[`adversarial-review`](../adversarial-review/SKILL.md). Apply this skill after
that routing decision has been made.

Planner citations are leads, not a closed evidence corpus. The reviewer must
inspect the repository independently, verify cited evidence, search for omitted
callers and consumers, and reconstruct the highest-risk relevant traces.

## Review the current state

Establish:

- externally observable intent and non-goals;
- canonical owners of affected types, contracts, configuration, and docs;
- current entry-to-outcome call paths and failure conversions;
- trust boundaries, actors, authority, and protected assets when applicable;
- platform, feature, lifecycle, disabled-state, and migration variants; and
- existing tests and the claims they actually prove.

Label concerns as a **confirmed conflict**, **design risk**, or **unverified
hypothesis**. Do not present a hypothesis as a current defect.

## Review the proposed design

Read the human review path first without relying on technical evidence
appendices. A human implementer or reviewer must be able to understand and
decide the goal, scope, key tradeoffs, architecture and ownership shape,
slices, risks, gaps, and prior review outcomes from that path. Report a material
decision hidden only in an appendix; do not report an appendix merely because
it contains supporting detail.

Then inspect the technical evidence. Verify that every decision, invariant,
trace, constructibility witness, and finding has one canonical stable ID and
definition, with references rather than divergent restatements. Treat word and
byte counts as review-cost diagnostics, not pass/fail limits, and reject
line-count reductions achieved through long table rows.

Challenge whether:

- terminology matches the owning repository context and avoids new synonyms;
- every affected invariant has one primary owner;
- important validation happens once at the boundary that can own it;
- proposed types and transitions prevent a reachable invalid state rather than
  merely adding abstraction;
- type-level claims survive compile-valid attempts to swap same-typed roles,
  supply multiple values with the same provenance, bypass constructors, and
  take illegal transitions;
- semantic traces include relevant success, denial, malformed, unavailable,
  disabled, alternate-entry, and bypass paths;
- compatibility, migration, and failure semantics are explicit;
- each vertical slice delivers independently verifiable behavior or bounded
  risk reduction;
- the artifact is decision-dense rather than a research transcript, and links
  supporting evidence instead of repeating it;
- slices with independent invariant owners or proof boundaries, acceptance
  outcomes, and implementation, review, and shipping paths are split into child
  plans, while deferred tactical detail is planned before its slice is
  implemented;
- durable facts are targeted to their canonical documentation owner; and
- the accepted artifact, findings, and dispositions will have a durable,
  team-accessible locator independent of the planning tool or conversation.

Conditional plan sections are required only when applicable. Independently
challenge an unsupported `Not applicable` decision, especially for trust,
compatibility, migration, type ownership, call traces, and proof obligations.

## Review proof obligations

For every material claim, check:

- the production entry or launch path used by the stimulus;
- observable outputs, side effects, state, decisions, and audit evidence;
- positive and negative controls needed to rule out vacuous success;
- substitutions, mocks, clocks, fixtures, and transports that narrow the claim;
- platform or configuration variants;
- existing, planned, or missing status; and
- what the proposed evidence does not prove.

Require the proof stimulus and assertion to establish the exact terminal
predicate in the invariant, not merely a successful proxy operation. For
ownership or lifecycle traces, follow every capability through success and
failure until it has an explicit terminal owner or is definitively consumed;
"state retained" or "cleanup attempted" does not establish who owns a live
capability after the function returns or its owner is dropped.

Type-level restrictions prove construction properties only. Runtime invariants
involving I/O, ordering, policy, configuration, trust, or error conversion need
runtime or boundary evidence.

For every unrepresentable-state claim, attempt to write a compile-valid illegal
witness against the proposed signatures. Distinguish what the shape proves
about cardinality, ownership uniqueness, semantic role or provenance, and
transition ordering. A pair of fields with different names but the same type,
for example, does not prove that callers cannot swap the values or provide two
values created for the same role.

## Rust modeling questions

When Rust design is involved, ask whether:

- a security or domain concept is an unconstrained raw primitive;
- `Option<T>` conflates absence, invalidity, and lifecycle state;
- a `bool` hides multiple states or legal transitions;
- validation is repeated because no canonical validated type owns it;
- exposed mutation can bypass an invariant owner;
- type, API, config, wire, event, and error names drift semantically; or
- public construction or transition APIs admit illegal states.

Use constructor-level witnesses when they make the concern concrete, for
example `Pair::new(right, left)` or `Pair::new(left_one, left_two)`. If the
witness compiles, identify the reachable producer and consumer before reporting
it; do not infer impact from type shape alone.

Report these only with a reachable correctness, security, compatibility,
operational, or recurring-maintenance impact. Do not report type-shape or naming
preferences alone.

## Findings

Return one severity-ordered report. Give each finding a stable `PLAN-NNN` ID and
include:

- severity, category, and classification;
- concrete file/line/symbol evidence or an explicit evidence gap;
- the reachable entry, conditions, causal path, and observable outcome;
- implicated invariant owner or trust boundary;
- practical impact;
- a concrete correction, research need, or user decision;
- confidence and unverified assumptions; and
- for material abstractions, the existing owner, consumers, operational role,
  lifecycle, cost, and replacement or non-goals.

Report only actionable findings. Do not duplicate concerns or report a style
preference without a causal impact. If there are no findings, say so and state
residual uncertainty or untested areas.

## Dispositions

Reviewer-authored finding fields are immutable. The planner may append a
disposition but must not erase or rewrite the original concern.

An evidence-backed factual repair may be incorporated with its finding,
rationale, and artifact location recorded. A choice that materially affects
product behavior, compatibility, security posture, migration, or a public
contract requires user direction. Rejected and deferred findings remain
visible with evidence.

After disposition, the accepted artifact and unchanged reviewer-authored
findings must be published at the durable locator named by the plan. The
implementation handoff and eventual pull request must repeat that locator. A
private chat or agent-thread link may supplement but not replace the
team-accessible artifact.

Pre-implementation review does not satisfy post-implementation adversarial
review of the actual diff.
