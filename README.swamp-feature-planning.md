# Repository-Aware Feature Planning

This Swamp extension turns one trusted, developer-authored Linear issue into a
reviewed implementation plan or an approval-gated child-issue decomposition.
Swamp owns lifecycle state and versioned artifacts. Linear is the collaborative
projection.

The author and every reviewer run as separate ephemeral Codex processes against
independent read-only snapshots of the same immutable Git or Jujutsu commit.
Codex tool calls can read the snapshot and minimal system paths, but cannot read
the operator's home directory. Linear credentials are resolved by Swamp and are
not forwarded to Codex.

## Prerequisites

- `swamp` and `codex` installed locally.
- `codex login status` reports an authenticated session.
- A Linear API key with issue, comment, upload, state, child-issue,
  and relation access.
- Team workflow-state UUIDs for every projected state.

Create a local encrypted vault and store the API credential:

```bash
swamp vault create local_encryption firma-feature-planning
swamp vault put firma-feature-planning linear-api-key '<key>'
```

Project and status UUIDs are non-secret deployment configuration in the planning
workflow YAML. Keep them out of the vault: marking them sensitive causes Swamp to
taint and redact persisted recovery data. The intake value is a comma-separated
allowlist. The model only changes the initial status when its UUID appears there.
Afterward it only changes a status that the same attempt previously confirmed as
model-owned. Unexpected human status changes are preserved.
The active projection then fails closed until Linear is returned to an allowed,
model-owned status.

The shipped workflow accepts `Prioritized` and `Triage`. A prioritized ticket
moves to `Triage` when planning starts and remains there through missing input,
review, failure, and decomposition approval. Starting the workflow again while
the ticket is in `Triage` creates or resumes a planning attempt. Explicit human
approval of an implementation plan, or successful creation of all decomposed
child issues, moves the parent to `In Progress`.

The project value is also a comma-separated UUID allowlist. Planning fails
closed before any Linear mutation when a ticket is unassigned or belongs to a
different project. Materialized child issues are explicitly assigned to the
parent ticket's allowed project.

## Configure A Repository

Every repository using the extension must commit both prompt-policy files:

```text
agent-constraints/planning-conventions.md
agent-constraints/adversarial-dimensions.md
```

The planning file defines repository architecture, implementation, testing, and
documentation conventions. The adversarial file defines repository-specific
review dimensions. Each file must be a regular, non-empty UTF-8 file no larger
than 32 KiB; symlinks are rejected. Missing or invalid files fail the attempt
before Codex runs.

The model reads both files from the same immutable revision used by the agents.
It persists their contents, paths, repository presentation settings, contract
version, and canonical digest in `prompt-policy-<attempt>`. Repairs, reviews, and
recovery use that frozen resource even if a later commit changes the files.

Configure these non-secret global arguments in the repository's planning
workflow:

- `repositoryDisplayName`
- `repositoryCommitUrlPrefix`, including the trailing slash
- `planningWorkflowName`
- `materializationWorkflowName`

The shipped workflow contains OpenFirma's values. Another repository can reuse
the same model with its own convention files, Linear UUIDs, repository URL, and
workflow presentation settings.

The workflow is manually started by a developer with board access, so the ticket
and human comments are trusted task instructions. Fixed controller requirements
still own read-only access, revision and identity binding, reviewer isolation,
and output schemas. Generated lifecycle comments are excluded from agent ticket
context; generated candidates and reviews remain untrusted data.

## Plan A Ticket

```bash
swamp workflow run @firma/feature-planning --input ticket_id=FIR-123
```

Optional `repository_revision` accepts a Git commit, Jujutsu commit ID, or
revision expression. The model resolves it once to an immutable commit ID.
Optional `trigger_event_id` deduplicates completed webhook-triggered attempts;
the same event may still resume an interrupted `planning` attempt.

Each new attempt gets a stable planning run UUID and one cumulative Linear
comment. Resuming or retrying a method updates that comment in place. Starting a
deliberate new attempt creates a new run UUID and comment. The comment shows
one bold status field, an optional primary artifact, and exact next-step commands.
This template is shared by every planning and materialization state. `Needs input`
uploads the detailed blocker analysis and questions as a required-input Markdown
artifact instead of expanding them in the comment. The collapsed `Planning
history` contains links to every intermediate candidate and adversarial review,
including the review findings. A collapsed `Run details` section contains the run
marker, links the immutable revision to GitHub, and links the point-in-time input
snapshot.

Candidates are uploaded as versioned Markdown files immediately after their
immutable Swamp candidate version is assigned. Reviews are uploaded immediately
after persistence. A separate typed `artifact` resource records each filename,
SHA-256 digest, upload URL, candidate version, and review attempt. Upload URLs do
not mutate candidate resources, so reviews remain bound to exactly the content
they assessed. Use `syncLinear` to retry missing uploads and reconstruct the
entire comment from persisted resources:

```bash
swamp model method run feature-plan-fir-123 syncLinear
```

The model is named from the normalized ticket, such as
`feature-plan-fir-123`. Inspect its state and outcome with:

```bash
swamp data get feature-plan-fir-123 state-main
swamp data get feature-plan-fir-123 outcome-main
```

Approve a reviewed implementation plan with the command shown in its comment:

```bash
swamp model method run feature-plan-fir-123 approvePlan
```

Approval records the explicit human transition, updates the cumulative comment,
and projects the configured `In Progress` Linear status. Rejecting a plan means
starting a deliberate new attempt:

```bash
swamp workflow run @firma/feature-planning --input ticket_id=FIR-123
```

## Materialize A Decomposition

Launch materialization with the candidate version and digest from the reviewed
outcome:

```bash
swamp workflow run @firma/feature-materialization \
  --input model_name=feature-plan-fir-123 \
  --input '{"candidate_version":3}' \
  --input plan_digest=<64-character-sha256> \
  --input approval_id=$(uuidgen | tr '[:upper:]' '[:lower:]')
```

The preparation resource is named `materialization-<approval-id>`. Inspect
that resource before approving. It contains the issue, digest, artifact URL,
child count, and ticket-drift warning. The current Swamp manual-approval prompt
cannot render deferred resource attributes, so the prompt itself is static.
The downstream method reads the approval-specific resource and the model rejects
an approval ID that is no longer active. Swamp does not yet provide a
cryptographic approval receipt; deployment permissions must still prevent
untrusted direct method calls or malicious resume-input replacement.

The materialization workflow continues updating the original planning comment.
It records the approval ID and digest, pre-gate ticket-drift warning, child identifiers,
dependency relations, redacted failures, and completion. It does not create a
separate materialization comment.

Approve and resume using the commands printed by Swamp. Reject the gate when the
decomposition is unsuitable. If a suspended run is abandoned rather than
rejected, return the model to `decomposition_ready` explicitly:

```bash
swamp model method run feature-plan-fir-123 cancelMaterialization
```

Partial child creation is reconciled by stable markers. Existing children are
never deleted automatically. Ambiguous or materially different matches fail and
require operator intervention.

## Verification

```bash
~/.swamp/deno/deno task check:feature-planning
~/.swamp/deno/deno task test:feature-planning
swamp workflow validate
swamp extension push manifest.yaml --dry-run
```
