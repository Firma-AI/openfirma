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

## Select the planning mode

Evaluate these rules in order. The first matching rule wins.

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

These triggers override Compact and None even when the diff is expected to be
small. A lower mode requires concrete repository evidence and a recorded
reason; it must not weaken a user-requested security posture or stable
contract.

### Compact

Use the compact workflow for bounded behavior changes when ownership and the
primary call path are known, no Full trigger applies, and one or two
implementation slices are expected.

Compact mode may combine research, design, and structure in one working
context. It still requires an independent plan review.

### None

Do not create a formal plan for:

- typos and prose-only corrections;
- formatting or generated-file refreshes;
- procedural metadata changes with an established workflow;
- behavior-preserving local refactors with no contract or invariant change; or
- single-site fixes whose cause, owner, call path, and regression proof are
  already established.

Confirm that no Full trigger applies. Record the reason in the thread or
handoff, then follow the repository's normal implementation and verification
guidance.

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

### 6. Assemble the candidate artifact

Write one candidate using the
[`design-plan-template`](reference/design-plan-template.md). Complete its
mandatory core. Include conditional sections only when their applicability
rules match, and explain risk-relevant `Not applicable` decisions.

### 7. Obtain independent plan review

Use a fresh reviewer and require it to load
[`reviewing-plans`](../reviewing-plans/SKILL.md). Give it:

- the task and explicit user constraints;
- the candidate artifact; and
- access to the repository revision it describes.

Do not give it hidden planner rationale, planner conclusions, or suggested
findings. Citations in the plan are leads, not the review boundary.

Preserve each finding and append its disposition. Evidence-backed factual
repairs may be incorporated only with the finding and repair recorded. Ask the
user to decide alternatives that materially affect product behavior,
compatibility, security posture, migration, or a public contract.

Plan review never replaces post-implementation adversarial review.

## Compact workflow

For Compact mode:

1. record the routing evidence;
2. combine repository research and design;
3. include only applicable program-design views;
4. produce one or two vertical slices with proof obligations;
5. assemble a concise artifact from the same template; and
6. obtain a fresh independent review using `reviewing-plans`.

Do not skip independent challenge merely because research and design shared a
context.

## Implementation handoff

Before implementation, ensure:

- every material Unknown is a visible gap or resolved decision;
- each affected invariant has one primary owner;
- runtime invariants have runtime or boundary proof obligations;
- slices have focused verification and can stand independently where feasible;
- durable facts target their canonical owning documentation; and
- plan findings and dispositions remain visible.

Implement slice by slice. If implementation evidence invalidates the design,
amend the artifact explicitly instead of silently diverging. After final
verification, follow [`adversarial-review`](../adversarial-review/SKILL.md) on
the actual change.
