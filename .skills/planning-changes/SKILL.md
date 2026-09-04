---
name: planning-changes
description: Plans substantial OpenFirma changes through proportional repository research, program design, proof obligations, vertical slices, and independent review. Use before implementing behavior, architecture, stable contracts, migrations, trust boundaries, or invariant-owner changes.
---

# Planning Changes

Use this skill to turn a substantial change request into one evidence-backed,
independently reviewed design plan before implementation. Keep the workflow
proportional: stage count is not a quality metric.

The final artifact follows the
[`design-plan-template`](reference/design-plan-template.md). Intermediate
questions, research notes, and drafts are transient unless the user requests
them or they contain durable facts that belong in an existing ADR,
architecture document, interface, or user guide.

For every Full or Compact change, the accepted artifact and its plan-review
findings become the first, plan-only commit owned by that pull request, relative
to an immutable ownership base recorded in the artifact. The durable locator is
the full commit SHA plus the plan path at that commit, preferably linked as a
repository blob URL pinned to that SHA. A path at `HEAD`, an agent thread, or a
private conversation is not a durable locator.

## Route the work

Evaluate the Full triggers before considering an exemption or Compact mode. A
Full trigger always requires formal planning, even for a single-site fix with a
known cause and call path.

### Full

Use the full workflow when the change affects any of these:

1. a security or trust boundary, secret path, or fail-closed behavior;
2. an externally observable stable API, CLI, configuration, wire, persisted
   data, or migration contract;
3. the owner or proof boundary of an invariant;
4. concurrency, lifecycle, recovery, ordering, or distributed behavior;
5. multiple crates or architectural boundaries with substantial uncertainty;
6. multiple viable designs with materially different tradeoffs; or
7. a current call path or repository contract that remains unclear or
   contradictory after initial inspection.

These triggers override Compact even when the diff is expected to be small. A
Compact choice where Full initially appears applicable requires concrete
repository evidence and a recorded reason; it must not weaken a user-requested
security posture or stable contract.

### Formal planning does not apply

When no Full trigger applies, do not create a formal plan for typos, prose-only
corrections, formatting, generated-file refreshes, procedural metadata changes
with an established workflow, behavior-preserving local refactors with no
contract or invariant change, or single-site fixes whose cause, owner, call
path, and regression proof are already established. Follow the repository's
normal implementation and verification guidance instead.

### Compact

Use the compact workflow for bounded behavior changes when ownership and the
primary call path are known, no Full trigger applies, and one or two
implementation slices are expected.

Compact mode may combine research, design, and structure in one working
context. It still requires an independent plan review.

## Plan artifact lifecycle

This section is the source of truth for formal-plan artifacts. It applies only
to Full and Compact work; it does not create artifacts for the no-plan
exemptions above.

### Establish the first commit

Before implementation begins:

1. Choose one stable repository-relative Markdown path. That is the only
   PR-owned plan path for the entire lifecycle; do not rename it, split it, or
   create a second plan path.
2. Record the intended ownership base in the plan. The first plan commit must
   have that exact commit as its parent and change only the stable plan path.
3. Obtain independent plan review and append every finding and disposition.
4. While review remains unresolved and no implementation commit exists, amend
   or replace that first commit at the same path as needed. If findings change
   the plan, update the first commit, record the resulting candidate commit's
   new full-SHA-and-path locator, and rerun review under the existing review
   rules.
5. Once the complete plan and disposition log are accepted, record the full
   ownership-base SHA, first-commit SHA, and path in the implementation handoff
   and PR body. Do not amend the plan commit merely to write its
   self-referential SHA into the plan.

No implementation, test, user documentation, migration, or behavior change
belongs in the plan commit. The first implementation commit ends the plan
commit's mutable phase. From then on, do not amend, reparent, squash, or
otherwise replace the accepted plan commit, its ownership base, or its
immutable locator.

If implementation evidence invalidates the accepted design, stop the affected
slice. Preserve the first commit, update the same stable plan path in a later
plan-only commit, record the amendment or superseding decision, obtain the
required independent review, and link both commit-pinned revisions. Do not
silently rewrite the accepted historical plan or create another plan path.
Keep the original accepted locator as provenance; the latest reviewed
same-path plan locator becomes the authority for the current implementation.

### Close the artifact

Keep the stable plan path available in the branch tip through implementation
verification, post-implementation adversarial review, and required finding
disposition. Once those are complete, add one final commit that deletes that
path and changes nothing else. This closing deletion is mechanical and does not
require another adversarial review; any later code, test, contract, or
documentation change means the PR was not actually closed and the lifecycle
must be reopened before review resumes.

The closing deletion commit must be the immediate child of the exact
independently reviewed implementation tip. Any code, test, contract,
documentation, or behavior change after that review invalidates the reviewed
tip evidence; obtain a fresh review before recreating the closing commit.

The final PR tip and effective base-to-tip diff must contain no PR-owned plan
Markdown. The add-then-delete sequence is absent from the final tree and
effective diff. A merge strategy that preserves the branch commits can still
retain the historical plan commit in ancestry; never claim that deletion
erases it from Git history.

After approval and merge, code, tests, user-facing documentation, migration
documentation, and stable contracts are the maintained source of truth. The
commit-pinned plan is historical context, not maintained documentation, and
must not remain in the checked-out tree on the target branch.

### Stacked pull requests and base changes

Route every PR in a stack independently. Each Full or Compact PR records its own
immutable ownership base and stable plan path, then owns its own first plan-only
commit and closing deletion-only commit. Prefer creating a descendant from the
ancestor PR's closed tip so ancestor plans are already absent. Before accepting
a descendant, list all ancestor plan paths and verify that its tip does not
reintroduce any of them.

While a plan is unresolved and implementation has not begun, restack bottom-up,
replace the affected first commit, update the prospective locator, and rerun
plan review. After implementation begins, preserve each accepted plan commit
SHA and its recorded ownership base. Integrate ancestor or target-branch changes
without rewriting that ownership history. A squash- or rebase-merged ancestor
can make the current GitHub base-to-tip commit range include historical ancestor
commits; the recorded ownership base, not the rewritten GitHub base, still
defines which first commit this PR owns. This does not require a global
commit-preserving merge policy.

After every base update, verify the lifecycle both against the immutable
ownership base and against the current PR diff, and confirm that ancestor plan
paths remain absent from the descendant tip. If maintainers require a clean
current-base range that cannot preserve the accepted ownership history, stop
and create a replacement PR with a newly reviewed plan and locator. Never
silently rewrite the accepted plan SHA to make the range look clean.

## Full workflow

### 1. Questions

Translate the request into implementation-neutral research questions. Cover:

- user or operator outcomes and externally observable behavior;
- affected terminology, states, invariants, and ownership boundaries;
- entry points, consumers, failure paths, and platform variants;
- stable compatibility surfaces and migrations;
- existing tests and proof boundaries; and
- genuine decisions that repository evidence cannot answer.

Do not ask the user questions that direct inspection can answer.

### 2. Research

Use a fresh research context when separating the task's proposed solution from
current-state investigation would reduce confirmation bias. Give it the
approved questions, not design conclusions.

For each answer:

- cite files and symbols, with line references when stable;
- label the claim **Observed**, **Inferred**, or **Unknown**;
- trace behavior from relevant entry points to observable outcomes;
- identify types before and after meaningful boundaries;
- locate validation, trust transitions, invariant owners, and tests; and
- pin durable research artifacts to the inspected revision.

Research describes what exists. Keep design recommendations in the next stage.

### 3. Design

Define the desired state using canonical repository terminology. Record:

- intended behavior and explicit non-goals;
- affected invariants and their primary owners;
- compatibility, migration, and failure semantics;
- viable alternatives, tradeoffs, and rejected choices when material;
- assumptions that remain unproved; and
- the decisions with the least confidence.

Do not silently convert an Unknown into an assumption.

### 4. Program design and structure

Describe the shape of important code before implementation bodies:

- a file-tree diff when placement or ownership changes;
- key types, enums, traits, and function signatures;
- curated current and proposed semantic call traces;
- validation and trust-boundary crossings;
- invariant proof obligations; and
- test names, stimuli, and observable assertions.

Use types to make invalid states harder to express when that removes a
reachable defect or repeated validation. Do not mandate newtypes, typestate, or
domain abstractions without a concrete ownership and lifecycle benefit.

For every claim that a type makes an invalid state unrepresentable, perform a
constructibility attack. Distinguish cardinality, ownership uniqueness,
semantic role or provenance, and legal transition ordering. Write compile-valid
pseudocode for plausible illegal constructions, including swapped same-typed
roles and repeated values from the wrong provenance. If an illegal witness
compiles, narrow the claim and select role-specific types, validating
constructors, or runtime proof as appropriate.

Call traces are not exhaustive call graphs. Follow only the paths needed to
establish reachability, semantic transformations, invariant ownership, failure
mapping, and externally observable effects.

### 5. Plan vertical slices

Each slice must deliver independently verifiable behavior or bounded risk
reduction. Keep its type or API changes, production behavior, tests, and
directly related documentation or configuration together.

For every slice state:

- the observable capability or invariant it delivers;
- expected files and affected semantic trace;
- proof obligations and focused verification;
- dependencies on earlier slices; and
- what remains intentionally unsupported.

Avoid horizontal phases such as all types, then all implementations, then all
tests unless a compilation or migration constraint requires them.

### Control scope and detail

Judge a plan by decision density and cohesion, not line count. Every section or
record must resolve a design decision, establish or locate a proof obligation,
define an executable slice, or expose a material gap. Cite supporting evidence
instead of repeating research narration; place necessary inventories and raw
evidence in a linked appendix when they would obscure the design.

Optimize the main review path for a human implementer or reviewer. It must
stand on its own for understanding and deciding the goal, scope, key tradeoffs,
architecture and ownership shape, implementation slices, risks, gaps, and
review outcomes. Put type sketches, constructibility witnesses, expanded
traces, proof matrices, test inventories, and research evidence in technical
evidence appendices unless a small excerpt is essential to a design decision.
The appendices support deeper review and agent handoff; they must not hide a
material decision from the human review path.

Give each decision, invariant, trace, constructibility witness, and finding one
canonical stable ID and definition. Other sections reference those IDs instead
of restating the content. Before independent review, perform a deduplication
pass. When scope or verbosity is in question, compare main-path and appendix
word and byte counts as diagnostics, not limits. Long table rows do not count as
compression.

Split a slice into a child plan when it has its own invariant owner or proof
boundary, an independently observable acceptance outcome, and can be
implemented, reviewed, and shipped without the rest of the parent. Separate
compatibility, rollback, or failure decisions are additional evidence for a
split, not prerequisites. The parent retains the cross-slice contract,
dependencies, and integration proof obligations.

Plan at coarser granularity when a later slice's tactical choices depend on
evidence produced by an earlier slice. Record the boundary, acceptance outcome,
and decision to defer; complete and review the child plan before implementing
that slice. Keep work in one plan when splitting would require a knowingly
invalid intermediate state or obscure one invariant that must change atomically
across boundaries.

### 6. Assemble the candidate artifact

Write one candidate using the
[`design-plan-template`](reference/design-plan-template.md). Complete its
mandatory core. Include conditional sections only when their applicability
rules match, and explain risk-relevant `Not applicable` decisions. Read the
human review path without its appendices before handoff; if a material decision
or dependency is understandable only from technical evidence, repair the main
path rather than expecting reviewers to reconstruct it.

### 7. Obtain independent plan review

Invoke [`adversarial-review`](../adversarial-review/SKILL.md) for the candidate
artifact and researched revision. It owns reviewer selection, independence, and
handoff isolation, and routes the review through
[`reviewing-plans`](../reviewing-plans/SKILL.md).

Preserve each finding and append its disposition. Evidence-backed factual
repairs may be incorporated only with the finding and repair recorded. Ask the
user to decide alternatives that materially affect product behavior,
compatibility, security posture, migration, or a public contract.

Plan review never replaces post-implementation adversarial review.

### 8. Establish the accepted plan commit

After dispositions are recorded, follow the plan artifact lifecycle above.
Make the complete accepted artifact and unchanged reviewer-authored findings
the PR's first plan-only commit. Record its full commit SHA and path in the
implementation handoff; the eventual PR description must link the same
commit-pinned artifact.

The artifact must record its status, repository-relative path, researched
revision, immutable ownership base, task or requirement source, any artifact it
supersedes, and the complete finding disposition log. The handoff records the
self-referential immutable locator after the commit exists.

## Compact workflow

For Compact mode:

1. record the routing evidence;
2. combine repository research and design;
3. include only applicable program-design views;
4. produce one or two vertical slices with proof obligations;
5. assemble a concise artifact from the same template;
6. obtain a fresh independent review using `reviewing-plans`; and
7. establish its accepted plan commit and immutable locator under the same
   lifecycle as Full mode.

Do not skip independent challenge merely because research and design shared a
context.

## Implementation handoff

Before implementation, ensure:

- the accepted artifact is the PR's first plan-only commit relative to its
  recorded ownership base and has a full commit-SHA-and-path locator;
- every material Unknown is a visible gap or resolved decision;
- each affected invariant has one primary owner;
- runtime invariants have runtime or boundary proof obligations;
- slices have focused verification and can stand independently where feasible;
- the scope and refinement assessment leaves no independently plannable change
  hidden inside an oversized slice;
- durable facts target their canonical owning documentation; and
- plan findings and dispositions remain visible.

Implement slice by slice without rewriting the accepted plan commit. Follow
the amendment rule above if implementation evidence invalidates the design.
After final verification, follow
[`adversarial-review`](../adversarial-review/SKILL.md) on the actual change,
dispose its findings, then create the mechanical closing deletion commit.
