# Design Plan Template

Use this template for Full and Compact plans. Keep the mandatory core concise.
Include conditional sections only when their applicability rule matches.

The mandatory core is the human review path. Optimize it for a human
implementer or reviewer; it must support a design decision without reading the
technical evidence appendices. Appendices support deep review, implementation,
and tool-agnostic agent handoff. Give each `DEC-*`, `INV-*`, `TRACE-*`, `CW-*`,
and `PLAN-*` item one canonical definition and reference its ID elsewhere
instead of repeating prose.

## Mandatory core

```markdown
# <Change title>

## Artifact metadata

- Status: Candidate | Accepted | Superseded
- Durable locator: <repository path or team-accessible URL>
- Repository revision researched: <revision>
- Task or requirement source: <locator>
- Supersedes: Not applicable | <locator>

## Goal and acceptance outcomes

- Goal:
- Observable acceptance outcomes:

## Scope

- In scope:
- Out of scope:
- Assumptions:
- Open decisions:
- Cohesion and split assessment:
- Deferred child plans: Not applicable | <boundary, acceptance outcome, and dependency>

## Routing

- Mode: Full | Compact
- Trigger evidence:
- Higher-mode triggers checked:
- Downgrade evidence and reason: Not applicable | <evidence>

## Current behavior and problem

- Owners and entry points:
- Current success and failure outcomes:
- Evidence: `path:symbol` or `path:line`

## Key decisions and tradeoffs

### `DEC-001`: <decision>

- Choice:
- Rationale and evidence:
- Consequences and rejected alternatives:

## Architecture and invariant ownership

- Architecture shape:

### `INV-001`: <invariant>

- Semantic predicate:
- Primary owner:
- Detailed proof: Not applicable | <technical-evidence anchor>

- Compatibility, migration, and failure semantics: <reference `DEC-*` IDs>
- Durable documentation owner:

## Implementation slices

### Slice 1: <observable capability or bounded risk reduction>

- Production, types, tests, and docs/config:
- Affected decisions and traces: <reference `DEC-*` and `TRACE-*` IDs>
- Proof obligations: <reference `INV-*` IDs>
- Focused verification:
- Dependencies:
- Intentionally unsupported:

## Risks and gaps

- Existing risks:
- Planned mitigations:
- Explicit evidence gaps:
- Least-confident decisions:

## Plan-review findings and dispositions

<Preserve reviewer-authored findings and append dispositions.>

The accepted artifact at the durable locator contains the complete disposition
log. Conversation links may provide supplementary context but are not the
handoff contract.

## Final verification

- Focused checks:
- Workspace checks:
- Post-implementation independent review:
```

Do not repeat technical evidence in the human review path. Include only the
architecture-shaping excerpt needed to understand a decision, then reference
its canonical appendix item. When scope or verbosity is disputed, use main-path
and appendix word and byte counts as diagnostics rather than budgets.

## Technical evidence appendices

Place applicable conditional sections after the mandatory core under a
`## Technical evidence` heading. A section may remain in the human review path
only when its complete content is necessary to decide the design. Research
inventories, expanded current-state traces, failure matrices, and test
inventories belong in appendices by default.

### Applicability assessment

Add this table before conditional sections:

| Section                     | Applicability               | Reason or evidence |
| --------------------------- | --------------------------- | ------------------ |
| Vocabulary                  | Applicable / Not applicable |                    |
| Alternatives                | Applicable / Not applicable |                    |
| File-tree diff              | Applicable / Not applicable |                    |
| Type and signature sketches | Applicable / Not applicable |                    |
| Semantic call traces        | Applicable / Not applicable |                    |
| Trust analysis              | Applicable / Not applicable |                    |
| Detailed proof obligations  | Applicable / Not applicable |                    |

Use these rules:

- **Vocabulary:** terms are introduced, changed, overloaded, or inconsistent
  across code, configuration, protocols, or documentation.
- **Alternatives:** more than one plausible design has a material tradeoff.
- **File-tree diff:** files are added, moved, or responsibility changes across
  modules.
- **Type and signature sketches:** type ownership, construction, transitions,
  or illegal-state concerns shape the design.
- **Semantic call traces:** behavior crosses components, validation stages,
  trust boundaries, or failure conversions.
- **Trust analysis:** actors, authority, protected assets, hostile input,
  secrets, or fail-closed behavior are involved.
- **Detailed proof obligations:** runtime, security, compatibility, migration,
  or operational invariants need evidence across suites or boundaries.

### Conditional: Vocabulary

| Canonical term | Meaning | Owner/context | Synonyms or terms to avoid | Conflict or decision |
| -------------- | ------- | ------------- | -------------------------- | -------------------- |
|                |         |               |                            |                      |

Keep meanings implementation-independent. Record only terms relevant to the
change rather than building a repository-wide glossary.

### Conditional: Alternatives

For each viable alternative record:

- shape and invariant owner;
- benefits and costs;
- compatibility and migration consequences;
- evidence supporting or weakening it; and
- why it was selected or rejected.

### Conditional: File-tree diff

```diff
 path
+├── new-file.rs       # NEW — owned responsibility
~├── changed-file.rs   # MODIFIED — changed responsibility
-└── old-file.rs       # REMOVED — responsibility moved or deleted
```

### Conditional: Types and signatures

Show architecture-shaping contracts without implementation bodies. State which
invalid states or duplicated checks the shape prevents. Do not sketch helpers
whose signatures do not affect ownership or review decisions.

For each unrepresentable-state claim, include the strongest plausible
compile-valid illegal construction. Check swapped same-typed roles, multiple
values with the same provenance, constructor bypasses, and illegal transitions.
State separately what the design proves about cardinality, ownership
uniqueness, semantic role or provenance, and transition ordering. If a witness
compiles, narrow the claim and record the validating boundary or revised type.
Give each witness a stable `CW-*` ID.

### Conditional: Semantic call traces

Use one record for each behaviorally significant current or proposed path:

| Field                      | Content                                         |
| -------------------------- | ----------------------------------------------- |
| Trace ID                   | `TRACE-<stable-name>`                           |
| State                      | Current / Proposed                              |
| Entry and stimulus         | External entry plus triggering input            |
| Path                       | `owner::operation → owner::operation → outcome` |
| Input/output types         | Types at meaningful boundaries                  |
| Validation/trust crossings | Validation and authority changes                |
| Invariant established      | Where and by which owner                        |
| Invariant assumed          | Downstream assumptions                          |
| Success outcome            | Observable result                               |
| Failure path               | Error mapping and fail-closed/open behavior     |
| Evidence                   | Files, symbols, tests, configuration            |
| Proof boundary             | Suite or component that can prove the claim     |
| Unknowns                   | Explicit gaps                                   |

Do not generate a comprehensive call graph. Include allowed, denied, malformed,
unavailable, or bypass paths only when they are relevant to the change.
For ownership and lifecycle paths, continue each success and failure trace to a
terminal owner or definitive consumption of every capability.

### Conditional: Trust analysis

Record actors, authority, supported workloads and deployment modes, attacker
capabilities, protected assets, trust transitions, and reachable abuse paths.
Distinguish accident-prevention guardrails from security boundaries.

### Conditional: Proof obligations

| Field                  | Content                                                          |
| ---------------------- | ---------------------------------------------------------------- |
| Invariant              | Reference the canonical `INV-*` definition in the human path     |
| Kind                   | Type / Runtime / Trust / Compatibility / Migration / Operational |
| Owner/proof boundary   | Component that establishes it                                    |
| Suite/boundary         | Unit, integration, E2E, protocol, config, or platform            |
| Stimulus               | Inputs and preconditions                                         |
| Observable effects     | Outputs, state, calls, denials, or events                        |
| Controls/substitutions | Mocks, clocks, transports, fixtures, or fault injection          |
| Failure cases          | Negative or adversarial path                                     |
| Evidence               | Existing type, test, or runtime evidence                         |
| Status                 | Existing / Planned / Gap                                         |
| Slice                  | Implementing slice                                               |
| Limits                 | What this evidence does not prove                                |

A type can prevent invalid construction. It does not by itself prove runtime
sequencing, I/O, configuration, policy evaluation, trust, or failure mapping.
Named fields or parameter positions also do not prove the provenance or
semantic role of same-typed values.
Proof assertions must establish the invariant's exact terminal predicate, not a
weaker proxy such as successful probing, signaling, or cleanup initiation.

### Plan-review finding record

```yaml
id: PLAN-001
severity: critical | high | medium | low
category: <category>
classification: confirmed-conflict | design-risk | unverified-hypothesis
claim: <actionable problem>
evidence:
  - <path, line, symbol, command, or explicit evidence gap>
reachability: <entry → conditions → affected outcome>
invariant_or_boundary: <owner or boundary>
impact: <practical effect>
correction: <artifact repair, research, or user decision>
confidence: high | medium | low
assumptions:
  - <unverified assumption>
```

The planner appends this separate block without modifying the reviewer-authored
record:

```yaml
disposition:
  status: accepted | corrected | rejected | deferred | user-decision-required
  rationale: <evidence-backed reason>
  incorporated_at: <artifact section or Not applicable>
  decided_by: planner | user
```

The disposition block is absent during review. Reviewer-authored fields remain
unchanged after it is appended. For a material abstraction recommendation, also
identify the existing owner, consumers, operational role, lifecycle, cost, and
what it replaces or does not solve.
