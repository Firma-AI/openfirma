# OpenFirma Feature Planning

This Swamp extension turns one Linear issue into a reviewed implementation plan
or an approval-gated child-issue decomposition. Swamp owns lifecycle state and
versioned artifacts. Linear is the collaborative projection.

The author and every reviewer run as separate ephemeral Codex processes against
independent read-only snapshots of the same immutable Git or Jujutsu commit.
Codex tool calls can read the snapshot and minimal system paths, but cannot read
the operator's home directory. Linear credentials are resolved by Swamp and are
not forwarded to Codex.

## Prerequisites

- `swamp` and `codex` installed locally.
- `codex login status` reports an authenticated session.
- A Linear API key with issue, comment, attachment, upload, state, child-issue,
  and relation access.
- Team workflow-state UUIDs for every projected state.

Create a local encrypted vault and store the credential and team configuration:

```bash
swamp vault create local_encryption openfirma-planning
swamp vault put openfirma-planning linear-api-key '<key>'
swamp vault put openfirma-planning linear-allowed-project-ids '<uuid>,<uuid>'
swamp vault put openfirma-planning linear-status-planning '<uuid>'
swamp vault put openfirma-planning linear-status-needs-input '<uuid>'
swamp vault put openfirma-planning linear-status-planning-failed '<uuid>'
swamp vault put openfirma-planning linear-status-awaiting-approval '<uuid>'
swamp vault put openfirma-planning linear-status-ready-for-implementation '<uuid>'
swamp vault put openfirma-planning linear-status-planned '<uuid>'
swamp vault put openfirma-planning linear-allowed-intake-status-ids '<uuid>,<uuid>'
```

The intake value is a comma-separated allowlist. The model only changes the
initial status when its UUID appears there. Afterward it only changes a status
that the same attempt previously confirmed as model-owned. Unexpected human
status changes are preserved.

The project value is also a comma-separated UUID allowlist. Planning fails
closed before any Linear mutation when a ticket is unassigned or belongs to a
different project. Materialized child issues are explicitly assigned to the
parent ticket's allowed project.

## Plan A Ticket

```bash
swamp workflow run @openfirma/feature-planning --input ticket_id=FIR-123
```

Optional `repository_revision` accepts a Git commit, Jujutsu commit ID, or
revision expression. The model resolves it once to an immutable commit ID.
Optional `trigger_event_id` deduplicates completed webhook-triggered attempts;
the same event may still resume an interrupted `planning` attempt.

The model is named from the normalized ticket, such as
`openfirma-plan-fir-123`. Inspect its state and outcome with:

```bash
swamp data get openfirma-plan-fir-123 state-main
swamp data get openfirma-plan-fir-123 outcome-main
```

## Materialize A Decomposition

Launch materialization with the candidate version and digest from the reviewed
outcome:

```bash
swamp workflow run @openfirma/feature-materialization \
  --input model_name=openfirma-plan-fir-123 \
  --input '{"candidate_version":3}' \
  --input plan_digest=<64-character-sha256> \
  --input approval_id=$(uuidgen | tr '[:upper:]' '[:lower:]')
```

The preparation resource is named `materialization-<approval-id>`. Inspect
that resource before approving. It contains the issue, digest, attachment URL,
child count, and ticket-drift warning. The current Swamp manual-approval prompt
cannot render deferred resource attributes, so the prompt itself is static.
The downstream method reads the approval-specific resource and the model rejects
an approval ID that is no longer active. Swamp does not yet provide a
cryptographic approval receipt; deployment permissions must still prevent
untrusted direct method calls or malicious resume-input replacement.

Approve and resume using the commands printed by Swamp. Reject the gate when the
decomposition is unsuitable. If a suspended run is abandoned rather than
rejected, return the model to `decomposition_ready` explicitly:

```bash
swamp model method run openfirma-plan-fir-123 cancelMaterialization
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
