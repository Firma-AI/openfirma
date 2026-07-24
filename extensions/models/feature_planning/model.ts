import { z } from "npm:zod@4.3.6";
import {
  AdapterError,
  ADVERSARIAL_DIMENSIONS_PATH,
  LinearClient,
  loadRepositoryPromptPolicy,
  PLANNING_CONVENTIONS_PATH,
  resolveRepositoryRevision,
  runAuthor,
  runReviewer,
} from "./adapters.ts";
import {
  buildAuthorPrompt,
  buildReviewerPrompt,
  canonicalJson,
  childMarker,
  planningRunMarker,
  planningTicketContent,
  renderDecomposition,
  renderPlan,
  renderReview,
  sha256,
} from "./helpers.ts";
import {
  type Artifact,
  ArtifactSchema,
  type Candidate,
  CandidateSchema,
  EffectSchema,
  type GlobalArgs,
  GlobalArgsSchema,
  type Materialization,
  MaterializationSchema,
  type Outcome,
  OutcomeSchema,
  type PlanningState,
  PlanningStateSchema,
  type PromptPolicy,
  PromptPolicySchema,
  type ReviewRecord,
  ReviewRecordSchema,
  StatusOwnershipSchema,
  type TicketBaseline,
  TicketBaselineSchema,
} from "./schemas.ts";

type DataHandle = {
  name: string;
  specName: string;
  version: number;
};

type Context = {
  modelType: string;
  modelId: string;
  methodName: string;
  repoDir: string;
  globalArgs: GlobalArgs;
  definition: { name: string };
  logger: {
    info: (message: string, properties: Record<string, unknown>) => void;
    warning: (message: string, properties: Record<string, unknown>) => void;
    error: (message: string, properties: Record<string, unknown>) => void;
  };
  writeResource: (
    specName: string,
    instanceName: string,
    data: Record<string, unknown>,
  ) => Promise<DataHandle>;
  readResource: (
    instanceName: string,
    version?: number,
  ) => Promise<Record<string, unknown> | null>;
  dataRepository: {
    findAllForModel: (
      type: string,
      modelId: string,
    ) => Promise<Array<{ name: string; version: number }>>;
    getContent: (
      type: string,
      modelId: string,
      dataName: string,
      version?: number,
    ) => Promise<Uint8Array | null>;
  };
};

const now = () => new Date().toISOString();

const materializationName = (workflowRunId: string) =>
  `materialization-${workflowRunId}`;

async function readState(context: Context): Promise<PlanningState | null> {
  const value = await context.readResource("state-main");
  return value ? PlanningStateSchema.parse(value) : null;
}

async function writeState(
  context: Context,
  state: PlanningState,
): Promise<DataHandle> {
  return await context.writeResource("state", "state-main", state);
}

async function readBaseline(context: Context): Promise<TicketBaseline | null> {
  const value = await context.readResource("ticket-baseline-main");
  return value ? TicketBaselineSchema.parse(value) : null;
}

async function readOutcome(context: Context): Promise<Outcome | null> {
  const value = await context.readResource("outcome-main");
  return value ? OutcomeSchema.parse(value) : null;
}

async function readPromptPolicy(
  context: Context,
  attempt: number,
): Promise<PromptPolicy | null> {
  const value = await context.readResource(`prompt-policy-${attempt}`);
  if (!value) return null;
  const policy = PromptPolicySchema.parse(value);
  if (await sha256(promptPolicyBinding(policy)) !== policy.digest) {
    throw new AdapterError(
      "conflict",
      "Persisted prompt policy digest does not match its content",
      false,
    );
  }
  return policy;
}

function promptPolicyBinding(
  policy: Omit<PromptPolicy, "digest" | "capturedAt">,
) {
  return {
    attempt: policy.attempt,
    repositoryRevision: policy.repositoryRevision,
    contractVersion: policy.contractVersion,
    repositoryDisplayName: policy.repositoryDisplayName,
    repositoryCommitUrlPrefix: policy.repositoryCommitUrlPrefix,
    planningWorkflowName: policy.planningWorkflowName,
    materializationWorkflowName: policy.materializationWorkflowName,
    planningConventionsPath: policy.planningConventionsPath,
    planningConventions: policy.planningConventions,
    adversarialDimensionsPath: policy.adversarialDimensionsPath,
    adversarialDimensions: policy.adversarialDimensions,
  };
}

export async function ensurePromptPolicy(
  context: Context,
  state: PlanningState,
  revision: string,
  vcs: "jj" | "git",
): Promise<{ state: PlanningState; policy: PromptPolicy }> {
  const existing = await readPromptPolicy(context, state.attempt);
  if (existing?.attempt === state.attempt) {
    if (
      existing.repositoryRevision !== revision ||
      (state.promptPolicyDigest && state.promptPolicyDigest !== existing.digest)
    ) {
      throw new AdapterError(
        "conflict",
        "Persisted prompt policy does not match the active planning attempt",
        false,
      );
    }
    if (state.promptPolicyDigest === existing.digest) {
      return { state, policy: existing };
    }
    const next = {
      ...state,
      promptPolicyDigest: existing.digest,
      updatedAt: now(),
    };
    await writeState(context, next);
    return { state: next, policy: existing };
  }
  const files = await loadRepositoryPromptPolicy(
    context.repoDir,
    revision,
    vcs,
  );
  const binding: Omit<PromptPolicy, "digest" | "capturedAt"> = {
    attempt: state.attempt,
    repositoryRevision: revision,
    contractVersion: "1" as const,
    repositoryDisplayName: context.globalArgs.repositoryDisplayName,
    repositoryCommitUrlPrefix: context.globalArgs.repositoryCommitUrlPrefix,
    planningWorkflowName: context.globalArgs.planningWorkflowName,
    materializationWorkflowName: context.globalArgs.materializationWorkflowName,
    planningConventionsPath: PLANNING_CONVENTIONS_PATH,
    planningConventions: files.planningConventions,
    adversarialDimensionsPath: ADVERSARIAL_DIMENSIONS_PATH,
    adversarialDimensions: files.adversarialDimensions,
  };
  const policy = PromptPolicySchema.parse({
    ...binding,
    digest: await sha256(promptPolicyBinding(binding)),
    capturedAt: now(),
  });
  await context.writeResource(
    "promptPolicy",
    `prompt-policy-${state.attempt}`,
    policy,
  );
  const next = {
    ...state,
    promptPolicyDigest: policy.digest,
    updatedAt: now(),
  };
  await writeState(context, next);
  return { state: next, policy };
}

export async function records<T>(
  context: Context,
  instanceName: string,
  schema: z.ZodType<T>,
): Promise<Array<{ version: number; value: T }>> {
  const metadata = await context.dataRepository.findAllForModel(
    context.modelType,
    context.modelId,
  );
  const latestVersion = metadata
    .filter((entry) => entry.name === instanceName)
    .reduce((latest, entry) => Math.max(latest, entry.version), 0);
  const output: Array<{ version: number; value: T }> = [];
  for (let version = 1; version <= latestVersion; version += 1) {
    const content = await context.dataRepository.getContent(
      context.modelType,
      context.modelId,
      instanceName,
      version,
    );
    if (content) {
      output.push({
        version,
        value: schema.parse(JSON.parse(new TextDecoder().decode(content))),
      });
    }
  }
  return output;
}

async function resourceNames(
  context: Context,
  prefix: string,
): Promise<string[]> {
  const metadata = await context.dataRepository.findAllForModel(
    context.modelType,
    context.modelId,
  );
  return [...new Set(metadata.map((entry) => entry.name))]
    .filter((name) => name.startsWith(prefix))
    .sort();
}

function linear(context: Context): LinearClient {
  return new LinearClient(
    context.globalArgs.linearApiUrl,
    context.globalArgs.linearApiKey,
  );
}

async function writeOutcome(
  context: Context,
  outcome: Outcome,
): Promise<DataHandle> {
  return await context.writeResource("outcome", "outcome-main", outcome);
}

async function runEffect(
  context: Context,
  state: PlanningState,
  key: string,
  input: unknown,
  operation: () => Promise<string | undefined>,
  options: { force?: boolean } = {},
): Promise<string | undefined> {
  const instanceName = `effect-${key}`;
  const inputDigest = await sha256({ attempt: state.attempt, input });
  const existingRaw = await context.readResource(instanceName);
  if (existingRaw) {
    const existing = EffectSchema.parse(existingRaw);
    if (
      !options.force &&
      existing.status === "confirmed" && existing.inputDigest === inputDigest
    ) {
      return existing.remoteId;
    }
  }
  const attempts = existingRaw
    ? EffectSchema.parse(existingRaw).attempts + 1
    : 1;
  await context.writeResource("effects", instanceName, {
    key,
    attempt: state.attempt,
    inputDigest,
    status: "pending",
    attempts,
    updatedAt: now(),
  });
  try {
    const remoteId = await operation();
    await context.writeResource("effects", instanceName, {
      key,
      attempt: state.attempt,
      inputDigest,
      status: "confirmed",
      remoteId,
      attempts,
      updatedAt: now(),
    });
    return remoteId;
  } catch (error) {
    await context.writeResource("effects", instanceName, {
      key,
      attempt: state.attempt,
      inputDigest,
      status: "failed",
      attempts,
      lastError: String(error),
      updatedAt: now(),
    });
    context.logger.warning("Linear projection effect failed", {
      key,
      error: String(error),
    });
    return undefined;
  }
}

async function publishArtifactEffect(
  context: Context,
  state: PlanningState,
  key: string,
  input: {
    issueId: string;
    filename: string;
    content: string;
    contentType: "application/json" | "text/markdown";
    digest: string;
  },
): Promise<string | undefined> {
  const instanceName = `effect-${key}`;
  const inputDigest = await sha256({ attempt: state.attempt, input });
  const existingRaw = await context.readResource(instanceName);
  const existing = existingRaw ? EffectSchema.parse(existingRaw) : null;
  if (
    existing?.status === "confirmed" && existing.inputDigest === inputDigest
  ) {
    return existing.remoteId;
  }
  const attempts = (existing?.attempts ?? 0) + 1;
  const client = linear(context);
  let assetUrl = existing?.inputDigest === inputDigest
    ? existing.remoteId
    : undefined;
  try {
    const current = await client.fetchIssue(
      state.issueIdentifier,
      state.attempt,
    );
    assertAllowedProject(context.globalArgs, current);
    if (current.id !== input.issueId) {
      throw new AdapterError(
        "conflict",
        "Linear issue identity changed before artifact projection",
        false,
      );
    }
    if (!assetUrl) {
      assetUrl = await client.uploadAsset(
        input.filename,
        input.content,
        input.contentType,
      );
      await context.writeResource("effects", instanceName, {
        key,
        attempt: state.attempt,
        inputDigest,
        status: "pending",
        remoteId: assetUrl,
        attempts,
        updatedAt: now(),
      });
    }
    await context.writeResource("effects", instanceName, {
      key,
      attempt: state.attempt,
      inputDigest,
      status: "confirmed",
      remoteId: assetUrl,
      attempts,
      updatedAt: now(),
    });
    return assetUrl;
  } catch (error) {
    await context.writeResource("effects", instanceName, {
      key,
      attempt: state.attempt,
      inputDigest,
      status: "failed",
      remoteId: assetUrl,
      attempts,
      lastError: String(error),
      updatedAt: now(),
    });
    context.logger.warning("Linear artifact projection failed", {
      key,
      error: String(error),
    });
    return undefined;
  }
}

async function readArtifacts(
  context: Context,
  attempt: number,
): Promise<Artifact[]> {
  const artifacts: Artifact[] = [];
  const names = await resourceNames(context, "artifact-");
  for (const name of names) {
    const raw = await context.readResource(name);
    if (raw) artifacts.push(ArtifactSchema.parse(raw));
  }
  return artifacts.filter((artifact) => artifact.attempt === attempt)
    .sort((left, right) => artifactKey(left).localeCompare(artifactKey(right)));
}

type ArtifactDraft =
  & {
    attempt: number;
    filename: string;
    contentType: "application/json" | "text/markdown";
    digest: string;
    content: string;
  }
  & (
    | { kind: "input_snapshot" }
    | { kind: "required_input" }
    | { kind: "candidate"; candidateVersion: number }
    | {
      kind: "review";
      candidateVersion: number;
      reviewAttempt: number;
    }
  );

function artifactKey(
  artifact: Artifact | ArtifactDraft,
): string {
  if (artifact.kind === "input_snapshot") {
    return `input-${artifact.attempt}`;
  }
  if (artifact.kind === "required_input") {
    return `required-input-${artifact.attempt}`;
  }
  if (artifact.kind === "candidate") {
    return `candidate-${artifact.candidateVersion}`;
  }
  return `review-${artifact.reviewAttempt}-candidate-${artifact.candidateVersion}`;
}

function artifactInstanceName(artifact: Artifact | ArtifactDraft): string {
  return `artifact-${artifactKey(artifact)}`;
}

function matchesArtifact(value: Artifact, draft: ArtifactDraft): boolean {
  if (value.kind !== draft.kind || value.digest !== draft.digest) return false;
  if (
    ["input_snapshot", "required_input"].includes(value.kind) &&
    value.kind === draft.kind
  ) {
    return true;
  }
  if (value.kind === "candidate" && draft.kind === "candidate") {
    return value.candidateVersion === draft.candidateVersion;
  }
  return value.kind === "review" && draft.kind === "review" &&
    value.candidateVersion === draft.candidateVersion &&
    value.reviewAttempt === draft.reviewAttempt;
}

async function persistArtifact(
  context: Context,
  state: PlanningState,
  baseline: TicketBaseline,
  artifact: ArtifactDraft,
): Promise<Artifact | null> {
  const existing = (await readArtifacts(context, state.attempt)).find((value) =>
    matchesArtifact(value, artifact)
  );
  if (existing?.status === "confirmed") return existing;
  const conflicting = (await readArtifacts(context, state.attempt)).find((
    value,
  ) =>
    artifactKey(value) === artifactKey(artifact) &&
    value.digest !== artifact.digest
  );
  if (conflicting) {
    throw new AdapterError(
      "conflict",
      `Artifact ${artifactKey(artifact)} changed after persistence`,
      false,
    );
  }
  const key = artifactKey(artifact);
  const common = {
    attempt: artifact.attempt,
    filename: artifact.filename,
    contentType: artifact.contentType,
    digest: artifact.digest,
    createdAt: existing?.createdAt ?? now(),
  };
  let pending: Artifact;
  switch (artifact.kind) {
    case "input_snapshot":
    case "required_input":
      pending = { ...common, kind: artifact.kind, status: "pending" };
      break;
    case "candidate":
      pending = {
        ...common,
        kind: artifact.kind,
        candidateVersion: artifact.candidateVersion,
        status: "pending",
      };
      break;
    case "review":
      pending = {
        ...common,
        kind: artifact.kind,
        candidateVersion: artifact.candidateVersion,
        reviewAttempt: artifact.reviewAttempt,
        status: "pending",
      };
      break;
  }
  const instanceName = artifactInstanceName(artifact);
  if (!existing) {
    await context.writeResource("artifact", instanceName, pending);
  }
  const url = await publishArtifactEffect(context, state, key, {
    issueId: baseline.id,
    filename: artifact.filename,
    content: artifact.content,
    contentType: artifact.contentType,
    digest: artifact.digest,
  });
  if (!url) return pending;
  const persisted = ArtifactSchema.parse({
    ...pending,
    status: "confirmed",
    url,
    uploadedAt: now(),
  });
  await context.writeResource("artifact", instanceName, persisted);
  return persisted;
}

function allowedIntakeStatusIds(globalArgs: GlobalArgs): Set<string> {
  return new Set(
    globalArgs.allowedIntakeStatusIdsCsv.split(",").map((value) => value.trim())
      .filter(Boolean),
  );
}

function assertAllowedIntakeStatus(
  globalArgs: GlobalArgs,
  ticket: TicketBaseline,
): void {
  if (!allowedIntakeStatusIds(globalArgs).has(ticket.stateId)) {
    throw new AdapterError(
      "conflict",
      `Linear issue ${ticket.identifier} is not in an allowed intake status`,
      false,
    );
  }
}

export function assertAllowedProject(
  globalArgs: GlobalArgs,
  ticket: TicketBaseline,
): asserts ticket is TicketBaseline & { projectId: string } {
  const allowed = new Set(
    globalArgs.allowedProjectIdsCsv.split(",").map((value) => value.trim())
      .filter(Boolean),
  );
  if (!ticket.projectId || !allowed.has(ticket.projectId)) {
    throw new AdapterError(
      "authorization",
      `Linear issue ${ticket.identifier} is outside the configured project allowlist`,
      false,
    );
  }
}

export async function projectStatus(
  context: Context,
  state: PlanningState,
  targetStatusId: string,
  force = false,
): Promise<boolean> {
  const client = linear(context);
  const statusId = await runEffect(
    context,
    state,
    `status-${state.phase}-${targetStatusId}`,
    {
      issueIdentifier: state.issueIdentifier,
      phase: state.phase,
      targetStatusId,
    },
    async () => {
      const current = await client.fetchIssue(
        state.issueIdentifier,
        state.attempt,
      );
      assertAllowedProject(context.globalArgs, current);
      const ownershipRaw = await context.readResource("status-ownership-main");
      const ownership = ownershipRaw
        ? StatusOwnershipSchema.parse(ownershipRaw)
        : null;
      const mayChange = current.stateId === targetStatusId ||
        (ownership?.attempt === state.attempt &&
          ownership.statusId === current.stateId) ||
        (state.initialStatusId === current.stateId &&
          allowedIntakeStatusIds(context.globalArgs).has(current.stateId));
      if (!mayChange) {
        context.logger.warning(
          "Preserving unexpected human-selected Linear status",
          {
            issue: state.issueIdentifier,
            currentStatusId: current.stateId,
            targetStatusId,
          },
        );
        throw new AdapterError(
          "conflict",
          "Linear status changed outside this planning attempt",
          false,
        );
      }
      if (current.stateId !== targetStatusId) {
        await client.updateStatus(current.id, targetStatusId);
      }
      await context.writeResource("statusOwnership", "status-ownership-main", {
        attempt: state.attempt,
        statusId: targetStatusId,
        updatedAt: now(),
      });
      return targetStatusId;
    },
    { force },
  );
  return statusId !== undefined;
}

type CommentProjection = {
  state: PlanningState;
  modelName: string;
  candidates: Array<{ version: number }>;
  reviews: ReviewRecord[];
  artifacts: Artifact[];
  outcome: Outcome | null;
  materialization: Materialization | null;
  repositoryCommitUrlPrefix: string;
  planningWorkflowName: string;
  materializationWorkflowName: string;
  ticketVisibleValues?: string[];
};

type ProjectionConfiguration = Pick<
  PromptPolicy,
  | "repositoryCommitUrlPrefix"
  | "planningWorkflowName"
  | "materializationWorkflowName"
>;

export function resolveProjectionConfiguration(
  state: PlanningState,
  policy: PromptPolicy | null,
  globalArgs: GlobalArgs,
): ProjectionConfiguration {
  if (
    state.promptPolicyDigest &&
    (!policy || policy.digest !== state.promptPolicyDigest)
  ) {
    throw new AdapterError(
      "conflict",
      "Current planning attempt has no matching frozen prompt policy",
      false,
    );
  }
  return policy ?? globalArgs;
}

function scrubTicketVisibleText(text: string, values: string[]): string {
  return [...new Set(values.filter((value) => value.length > 0))]
    .sort((left, right) => right.length - left.length)
    .reduce(
      (rendered, value) => rendered.replaceAll(value, "[ticket field]"),
      text,
    );
}

function escapeCommentMarkdown(text: string): string {
  return text
    .replace(/\s+/g, " ")
    .trim()
    .replace(/([a-z][a-z0-9+.-]*):\/\//gi, "$1: / /")
    .replace(/\bmailto:/gi, "mailto: ")
    .replace(/\bwww\./gi, "www . ")
    .replace(/([\\`*_{}[\]<>()[\]#+!|@~=&])/g, "\\$1")
    .replace(/^-+/, (value) => value.replaceAll("-", "\\-"))
    .replace(/^(\d+)\./, "$1\\.");
}

function phaseTitle(state: PlanningState, outcome: Outcome | null): string {
  if (outcome?.kind === "review_exhausted") return "Review exhausted";
  return {
    planning: "In progress",
    needs_input: "Needs input",
    implementation_ready: "Ready for review",
    implementation_approved: "Plan approved",
    decomposition_ready: "Decomposition ready",
    awaiting_approval: "Awaiting materialization approval",
    materializing: "Materializing",
    children_created: "Materialization complete",
    failed: "Failed",
  }[state.phase];
}

function recoveryAction(state: PlanningState, outcome: Outcome | null): string {
  if (state.phase === "implementation_ready") {
    return "Review and implement the final plan linked above.";
  }
  if (state.phase === "decomposition_ready") {
    return "Review the final decomposition and launch materialization when ready.";
  }
  if (state.phase === "implementation_approved") {
    return "Begin implementation from the approved plan.";
  }
  if (state.phase === "awaiting_approval") {
    return "Approve or reject the pending materialization workflow.";
  }
  if (state.phase === "materializing") {
    return "Re-run materialization with the same approval ID to resume reconciliation.";
  }
  if (state.phase === "children_created") {
    return "Continue implementation from the reconciled child issues.";
  }
  if (outcome?.kind === "needs_input") {
    return "Answer the blocking questions in a ticket comment, then start a new planning run.";
  }
  if (outcome?.kind === "review_exhausted") {
    return "Review the findings below, clarify the ticket, then start a new planning run.";
  }
  if (state.phase === "failed") {
    return "Re-run planning to start a new recoverable attempt. Raw agent and command errors are intentionally not copied to Linear.";
  }
  return "No action is required while planning is in progress.";
}

export function renderPlanningComment(input: CommentProjection): string {
  const { state, artifacts, outcome, materialization } = input;
  const clean = (text: string) =>
    escapeCommentMarkdown(
      scrubTicketVisibleText(text, input.ticketVisibleValues ?? []),
    );
  const finalVersion = outcome && [
      "implementation_ready",
      "implementation_approved",
      "decomposition_ready",
      "approval_stale",
      "children_created",
    ].includes(outcome.kind)
    ? outcome.candidateVersion
    : undefined;
  const finalArtifact = artifacts.find((artifact) =>
    artifact.kind === "candidate" &&
    artifact.candidateVersion === finalVersion && artifact.url
  );
  const snapshot = artifacts.find((artifact) =>
    artifact.kind === "input_snapshot" && artifact.url
  );
  const requiredInput = artifacts.find((artifact) =>
    artifact.kind === "required_input" && artifact.url
  );
  const marker = planningRunMarker(state.planningRunId);
  const revision = state.repositoryRevision;
  const runDetails = [
    "+++ Run details",
    `- Planning run: \`${marker}\``,
    revision
      ? `- Repository revision: [\`${revision}\`](${input.repositoryCommitUrlPrefix}${revision})`
      : "- Repository revision: pending",
    `- Attempt: ${state.attempt}`,
    `- Started: ${state.startedAt}`,
    `- Updated: ${state.updatedAt}`,
    ...(state.triggerEventId
      ? [`- Trigger event: \`${state.triggerEventId}\``]
      : []),
    ...(snapshot
      ? [
        "",
        "Input snapshot:",
        `[${snapshot.filename}](${snapshot.url})`,
        `SHA-256: \`${snapshot.digest}\``,
      ]
      : ["- Input snapshot: upload pending"]),
    "+++",
  ];

  const history: string[] = [
    `+++ Planning history (${input.candidates.length} candidate${
      input.candidates.length === 1 ? "" : "s"
    }, ${input.reviews.length} review${input.reviews.length === 1 ? "" : "s"})`,
  ];
  for (const candidate of input.candidates) {
    const artifact = artifacts.find((value) =>
      value.kind === "candidate" && value.candidateVersion === candidate.version
    );
    const final = candidate.version === finalVersion;
    history.push(
      `### Candidate v${candidate.version}${final ? " (final)" : ""}`,
      final
        ? "The final artifact is shown above."
        : artifact?.url
        ? `[${artifact.filename}](${artifact.url})\nSHA-256: \`${artifact.digest}\``
        : "Artifact upload pending",
    );
    for (
      const review of input.reviews.filter((value) =>
        value.report.candidateVersion === candidate.version
      )
    ) {
      const reviewArtifact = artifacts.find((value) =>
        value.kind === "review" &&
        value.candidateVersion === candidate.version &&
        value.reviewAttempt === review.reviewAttempt
      );
      history.push(
        `### Review ${review.reviewAttempt} of candidate v${candidate.version}`,
        `Verdict: **${review.report.verdict.replaceAll("_", " ")}**`,
        clean(review.report.summary),
        reviewArtifact?.url
          ? `[${reviewArtifact.filename}](${reviewArtifact.url})\nSHA-256: \`${reviewArtifact.digest}\``
          : "Review artifact upload pending",
      );
      for (const finding of review.report.findings) {
        history.push(
          `- **${clean(finding.id)} (${finding.severity}, ${
            clean(finding.category)
          })** at ${clean(finding.location)}: ${
            clean(finding.problem)
          } Required change: ${clean(finding.requiredChange)}`,
        );
      }
      if (review.report.residualRisks.length > 0) {
        history.push(
          `Residual risks: ${
            review.report.residualRisks.map(clean).join("; ")
          }`,
        );
      }
    }
  }
  if (input.candidates.length === 0 && input.reviews.length === 0) {
    history.push("No candidates have been persisted yet.");
  }
  history.push("+++");

  const body = [`**Status:** ${phaseTitle(state, outcome)}`];
  if (finalArtifact) {
    body.push(
      `**Plan:** [${finalArtifact.filename}](${finalArtifact.url})`,
      `**SHA-256:** \`${finalArtifact.digest}\``,
      `**Review:** Approved after ${state.completedReviewAttempts} adversarial review${
        state.completedReviewAttempts === 1 ? "" : "s"
      }`,
    );
    if (state.phase === "implementation_ready") {
      body.push(
        "",
        "**Suggested next steps:**",
        `- Approve: \`swamp model method run ${input.modelName} approvePlan\``,
        `- Reject and replan: \`swamp workflow run ${input.planningWorkflowName} --input ticket_id=${state.issueIdentifier}\``,
      );
    } else if (
      state.phase === "decomposition_ready" && outcome?.candidateVersion &&
      outcome.planDigest
    ) {
      body.push(
        "",
        "**Suggested next steps:**",
        `- Approve: \`swamp workflow run ${input.materializationWorkflowName} --input model_name=${input.modelName} --input '{"candidate_version":${outcome.candidateVersion}}' --input plan_digest=${outcome.planDigest} --input approval_id=$(uuidgen | tr '[:upper:]' '[:lower:]')\``,
        `- Reject and replan: \`swamp workflow run ${input.planningWorkflowName} --input ticket_id=${state.issueIdentifier}\``,
      );
    }
  }
  if (outcome?.kind === "needs_input" && outcome.blockingQuestions) {
    body.push(
      "",
      requiredInput?.url
        ? `**Required input:** [${requiredInput.filename}](${requiredInput.url})`
        : "**Required input:** upload pending",
      "",
      "**Suggested next steps:**",
      "- Update the ticket with the requested information.",
      `- Retry planning: \`swamp workflow run ${input.planningWorkflowName} --input ticket_id=${state.issueIdentifier}\``,
    );
  } else if (outcome?.kind === "review_exhausted") {
    body.push("", "Human action is required after three adversarial reviews.");
  } else if (outcome?.kind === "failed") {
    body.push(
      "",
      "Planning or materialization failed. Completed artifacts and review findings remain available below.",
    );
  }
  if (materialization) {
    body.push(
      "",
      "**Materialization:**",
      `- Approval ID: \`${materialization.workflowRunId}\``,
      `- Approved digest: \`${materialization.planDigest}\``,
      `- Ticket drift detected: ${materialization.ticketChangedSincePlanning}`,
      `- State: ${materialization.cancelledAt ? "cancelled" : state.phase}`,
      `- Children: ${
        Object.entries(materialization.childIds).length === 0
          ? "none yet"
          : Object.keys(materialization.childIds).map((key) =>
            `${key}=\`${materialization.childIdentifiers[key]}\``
          ).join(", ")
      }`,
      `- Dependencies: ${
        materialization.relationKeys.length === 0
          ? "none"
          : materialization.relationKeys.join(", ")
      }`,
    );
  }
  const diagnostics = [
    "+++ Diagnostics and recovery",
    `- Last durable phase: \`${state.phase}\``,
    `- Candidates persisted: ${input.candidates.length}`,
    `- Reviews completed: ${state.completedReviewAttempts}/3`,
    `- Artifacts uploaded: ${artifacts.length}`,
    `- Next action: ${recoveryAction(state, outcome)}`,
    `- Recovery: run \`${input.planningWorkflowName}\` again for this ticket.`,
    "+++",
  ];
  return [
    ...body,
    "",
    ...runDetails,
    "",
    ...history,
    "",
    ...diagnostics,
  ].join("\n");
}

async function latestMaterialization(
  context: Context,
  attempt: number,
): Promise<Materialization | null> {
  const values: Materialization[] = [];
  for (const name of await resourceNames(context, "materialization-")) {
    const raw = await context.readResource(name);
    if (raw) {
      const value = MaterializationSchema.parse(raw);
      if (value.attempt === attempt) values.push(value);
    }
  }
  return values.sort((left, right) =>
    left.preparedAt.localeCompare(right.preparedAt)
  ).at(-1) ?? null;
}

async function projectLifecycleComment(
  context: Context,
  state: PlanningState,
  force = false,
): Promise<boolean> {
  const client = linear(context);
  const marker = planningRunMarker(state.planningRunId);
  const artifacts = await readArtifacts(context, state.attempt);
  const candidates = (await records(context, "candidate-main", CandidateSchema))
    .filter((record) => record.value.attempt === state.attempt)
    .map((record) => record.version)
    .sort((left, right) => left - right)
    .map((version) => ({ version }));
  const reviews = (await records(context, "review-main", ReviewRecordSchema))
    .map((record) => record.value)
    .filter((review) => review.attempt === state.attempt);
  reviews.sort((left, right) => left.reviewAttempt - right.reviewAttempt);
  const outcome = await readOutcome(context);
  const baseline = await readBaseline(context);
  const policy = await readPromptPolicy(context, state.attempt);
  const projection = resolveProjectionConfiguration(
    state,
    policy,
    context.globalArgs,
  );
  const body = renderPlanningComment({
    state,
    modelName: context.definition.name,
    candidates,
    reviews,
    artifacts,
    outcome: outcome?.attempt === state.attempt ? outcome : null,
    materialization: await latestMaterialization(context, state.attempt),
    repositoryCommitUrlPrefix: projection.repositoryCommitUrlPrefix,
    planningWorkflowName: projection.planningWorkflowName,
    materializationWorkflowName: projection.materializationWorkflowName,
    ticketVisibleValues: baseline
      ? [
        baseline.identifier,
        baseline.title,
        baseline.url,
        baseline.projectName ?? "",
      ]
      : [],
  });
  const commentId = await runEffect(
    context,
    state,
    "lifecycle-comment",
    { marker, body },
    async () => {
      const current = await client.fetchIssue(
        state.issueIdentifier,
        state.attempt,
      );
      assertAllowedProject(context.globalArgs, current);
      return await client.upsertLifecycleComment(current, marker, body);
    },
    { force },
  );
  return commentId !== undefined;
}

export async function projectPhase(
  context: Context,
  state: PlanningState,
  statusId: string,
  forceComment = false,
): Promise<void> {
  const phase = await runEffect(
    context,
    state,
    `phase-${state.phase}`,
    { statusId, stateUpdatedAt: state.updatedAt, forceComment },
    async () => {
      const statusConfirmed = await projectStatus(
        context,
        state,
        statusId,
        forceComment,
      );
      if (!statusConfirmed) {
        throw new AdapterError(
          "temporary",
          "Linear status projection is not confirmed",
          true,
        );
      }
      const commentConfirmed = await projectLifecycleComment(
        context,
        state,
        forceComment,
      );
      if (!commentConfirmed) {
        throw new AdapterError(
          "temporary",
          "Linear phase projection is not fully confirmed",
          true,
        );
      }
      return state.phase;
    },
    { force: forceComment },
  );
  if (!phase) {
    throw new AdapterError(
      "temporary",
      "Linear phase projection is not fully confirmed",
      true,
    );
  }
}

async function phaseProjectionIncomplete(
  context: Context,
  state: PlanningState,
): Promise<boolean> {
  const raw = await context.readResource(`effect-phase-${state.phase}`);
  const effect = raw ? EffectSchema.parse(raw) : null;
  return effect?.attempt !== state.attempt || effect.status !== "confirmed";
}

function assertCandidateIdentity(
  candidate: Candidate,
  state: PlanningState,
  revision: string,
): void {
  if (
    candidate.attempt !== state.attempt ||
    candidate.plan.attempt !== state.attempt ||
    candidate.plan.ticket !== state.issueIdentifier ||
    candidate.plan.repositoryRevision !== revision
  ) {
    throw new AdapterError(
      "invalid_output",
      "Codex returned a candidate with mismatched attempt, ticket, or repository revision",
      false,
    );
  }
}

async function persistAuthorResult(
  context: Context,
  state: PlanningState,
  baseline: TicketBaseline,
  revision: string,
  vcs: "jj" | "git",
  policy: PromptPolicy,
  previous?: { candidate: Candidate; review: ReviewRecord },
): Promise<{ state: PlanningState; candidate?: Candidate; stop: boolean }> {
  const authorRound = previous ? previous.candidate.authorRound + 1 : 1;
  const result = await runAuthor({
    repoDir: context.repoDir,
    revision,
    vcs,
    globalArgs: context.globalArgs,
    prompt: buildAuthorPrompt(
      baseline,
      revision,
      state.attempt,
      policy,
      previous
        ? { candidate: previous.candidate, review: previous.review.report }
        : undefined,
    ),
  });
  if (result.kind === "needs_input") {
    const next = { ...state, phase: "needs_input" as const, updatedAt: now() };
    const outcome: Outcome = {
      attempt: state.attempt,
      kind: "needs_input",
      summary: result.summary,
      blockingQuestions: result.blockingQuestions,
      updatedAt: now(),
    };
    await writeOutcome(context, outcome);
    await writeState(context, next);
    const artifact = await persistRequiredInputArtifact(
      context,
      next,
      baseline,
      result.summary,
      result.blockingQuestions,
    );
    if (!artifact?.url) {
      throw new AdapterError(
        "temporary",
        "The required-input artifact is not confirmed in Linear",
        true,
      );
    }
    await projectPhase(
      context,
      next,
      context.globalArgs.statusIds.triage,
    );
    return { state: next, stop: true };
  }

  const candidate = {
    ...result,
    attempt: state.attempt,
    authorRound,
  } as Candidate;
  assertCandidateIdentity(candidate, state, revision);
  const handle = await context.writeResource(
    "candidate",
    "candidate-main",
    candidate,
  );
  const next = {
    ...state,
    currentCandidateVersion: handle.version,
    updatedAt: now(),
  };
  await writeState(context, next);
  await persistCandidateArtifact(
    context,
    next,
    baseline,
    candidate,
    handle.version,
  );
  await projectLifecycleComment(context, next);
  return { state: next, candidate, stop: false };
}

function candidateFilename(
  candidate: Candidate,
  version: number,
): string {
  const kind = candidate.kind === "implementation_plan"
    ? "implementation-plan"
    : "decomposition-plan";
  return `${kind}-v${version}.md`;
}

async function persistCandidateArtifact(
  context: Context,
  state: PlanningState,
  baseline: TicketBaseline,
  candidate: Candidate,
  candidateVersion: number,
): Promise<Artifact | null> {
  const digest = await sha256(candidate.plan);
  const content = candidate.kind === "implementation_plan"
    ? renderPlan(candidate.plan, digest)
    : renderDecomposition(candidate.plan, digest);
  return await persistArtifact(context, state, baseline, {
    attempt: state.attempt,
    kind: "candidate",
    candidateVersion,
    filename: candidateFilename(candidate, candidateVersion),
    contentType: "text/markdown",
    digest,
    content,
  });
}

async function persistReviewArtifact(
  context: Context,
  state: PlanningState,
  baseline: TicketBaseline,
  review: ReviewRecord,
): Promise<Artifact | null> {
  const report = review.report;
  return await persistArtifact(context, state, baseline, {
    attempt: state.attempt,
    kind: "review",
    candidateVersion: report.candidateVersion,
    reviewAttempt: review.reviewAttempt,
    filename:
      `review-${review.reviewAttempt}-candidate-v${report.candidateVersion}.md`,
    contentType: "text/markdown",
    digest: await sha256(report),
    content: renderReview(report),
  });
}

function renderRequiredInput(
  summary: string,
  questions: NonNullable<Outcome["blockingQuestions"]>,
): string {
  return [
    "# Required Input",
    "",
    "## Why Planning Is Blocked",
    summary,
    "",
    "## Questions",
    ...questions.flatMap((question, index) => [
      `### ${index + 1}. ${question.question}`,
      question.whyBlocking,
      "",
    ]),
  ].join("\n");
}

async function persistRequiredInputArtifact(
  context: Context,
  state: PlanningState,
  baseline: TicketBaseline,
  summary: string,
  questions: NonNullable<Outcome["blockingQuestions"]>,
): Promise<Artifact | null> {
  const content = renderRequiredInput(summary, questions);
  return await persistArtifact(context, state, baseline, {
    attempt: state.attempt,
    kind: "required_input",
    filename: `required-input-attempt-${state.attempt}.md`,
    contentType: "text/markdown",
    digest: await sha256({ summary, questions }),
    content,
  });
}

async function persistInputSnapshot(
  context: Context,
  state: PlanningState,
  baseline: TicketBaseline,
  policy: PromptPolicy,
): Promise<Artifact | null> {
  const snapshot = {
    planningRunId: state.planningRunId,
    attempt: state.attempt,
    repositoryRevision: state.repositoryRevision,
    promptPolicy: {
      digest: policy.digest,
      contractVersion: policy.contractVersion,
      repositoryDisplayName: policy.repositoryDisplayName,
      planningConventionsPath: policy.planningConventionsPath,
      adversarialDimensionsPath: policy.adversarialDimensionsPath,
    },
    capturedAt: baseline.capturedAt,
    ticketUpdatedAt: baseline.updatedAt,
    ticket: planningTicketContent(baseline),
  };
  return await persistArtifact(context, state, baseline, {
    attempt: state.attempt,
    kind: "input_snapshot",
    filename: `planning-input-attempt-${state.attempt}.json`,
    contentType: "application/json",
    digest: await sha256(snapshot),
    content: `${
      JSON.stringify(JSON.parse(canonicalJson(snapshot)), null, 2)
    }\n`,
  });
}

async function publishApproved(
  context: Context,
  state: PlanningState,
  baseline: TicketBaseline,
  candidate: Candidate,
  candidateVersion: number,
): Promise<PlanningState> {
  const digest = await sha256(candidate.plan);
  const implementation = candidate.kind === "implementation_plan";
  const artifact = await persistCandidateArtifact(
    context,
    state,
    baseline,
    candidate,
    candidateVersion,
  );
  if (!artifact) {
    context.logger.warning(
      "Approved plan is persisted but its Linear artifact link is pending",
      {
        candidateVersion,
      },
    );
  }
  const next: PlanningState = {
    ...state,
    phase: implementation ? "implementation_ready" : "decomposition_ready",
    updatedAt: now(),
  };
  const outcome: Outcome = {
    attempt: state.attempt,
    kind: implementation ? "implementation_ready" : "decomposition_ready",
    summary: implementation
      ? "Reviewed implementation plan is ready"
      : "Reviewed decomposition is ready for human approval",
    candidateVersion,
    planDigest: digest,
    artifactUrl: artifact?.url,
    updatedAt: now(),
  };
  await writeOutcome(context, outcome);
  await writeState(context, next);
  await projectPhase(
    context,
    next,
    context.globalArgs.statusIds.triage,
  );
  return next;
}

async function executePlan(
  args: {
    ticketId: string;
    repositoryRevision?: string;
    triggerEventId?: string;
  },
  context: Context,
): Promise<{ dataHandles: DataHandle[] }> {
  let state = await readState(context);
  const requestedTicket = args.ticketId.toUpperCase();
  if (state && state.issueIdentifier !== requestedTicket) {
    throw new Error(
      `Model ${context.definition.name} belongs to ${state.issueIdentifier}, not ${args.ticketId}`,
    );
  }
  if (
    state?.phase !== "planning" &&
    state?.triggerEventId &&
    state.triggerEventId === args.triggerEventId
  ) {
    context.logger.info("Synchronizing duplicate planning trigger", {
      triggerEventId: args.triggerEventId,
    });
    return await syncLinear(context);
  }
  if (state && ["awaiting_approval", "materializing"].includes(state.phase)) {
    throw new Error(`plan cannot run while phase is ${state.phase}`);
  }
  if (
    state && state.phase !== "planning" &&
    await phaseProjectionIncomplete(context, state)
  ) {
    return await syncLinear(context);
  }

  if (!state || state.phase !== "planning") {
    const attempt = (state?.attempt ?? 0) + 1;
    const baseline = await linear(context).fetchIssue(requestedTicket, attempt);
    assertAllowedProject(context.globalArgs, baseline);
    assertAllowedIntakeStatus(context.globalArgs, baseline);
    state = {
      issueIdentifier: requestedTicket,
      attempt,
      planningRunId: crypto.randomUUID(),
      startedAt: now(),
      phase: "planning",
      completedReviewAttempts: 0,
      triggerEventId: args.triggerEventId || undefined,
      initialStatusId: baseline.stateId,
      updatedAt: now(),
    };
    await context.writeResource(
      "ticketBaseline",
      "ticket-baseline-main",
      baseline,
    );
    await writeState(context, state);
  }

  const persistedOutcome = await readOutcome(context);
  if (persistedOutcome?.attempt === state.attempt) {
    const outcomePhase = {
      needs_input: "needs_input",
      review_exhausted: "needs_input",
      implementation_ready: "implementation_ready",
      implementation_approved: "implementation_approved",
      decomposition_ready: "decomposition_ready",
      approval_stale: "decomposition_ready",
      children_created: "children_created",
      failed: "failed",
    }[persistedOutcome.kind] as PlanningState["phase"];
    if (state.phase === "planning") {
      await writeState(context, {
        ...state,
        phase: outcomePhase,
        updatedAt: now(),
      });
      return await syncLinear(context);
    }
  }

  try {
    let baseline = await readBaseline(context);
    if (!baseline || baseline.attempt !== state.attempt) {
      baseline = await linear(context).fetchIssue(
        state.issueIdentifier,
        state.attempt,
      );
      assertAllowedProject(context.globalArgs, baseline);
      assertAllowedIntakeStatus(context.globalArgs, baseline);
      await context.writeResource(
        "ticketBaseline",
        "ticket-baseline-main",
        baseline,
      );
      state = {
        ...state,
        initialStatusId: baseline.stateId,
        updatedAt: now(),
      };
      await writeState(context, state);
    }

    const resolved = state.repositoryRevision
      ? await resolveRepositoryRevision(
        context.repoDir,
        state.repositoryRevision,
      )
      : await resolveRepositoryRevision(
        context.repoDir,
        args.repositoryRevision || undefined,
      );
    if (!state.repositoryRevision) {
      state = {
        ...state,
        repositoryRevision: resolved.revision,
        updatedAt: now(),
      };
      await writeState(context, state);
    }
    const ensuredPolicy = await ensurePromptPolicy(
      context,
      state,
      resolved.revision,
      resolved.vcs,
    );
    state = ensuredPolicy.state;
    const policy = ensuredPolicy.policy;
    await persistInputSnapshot(context, state, baseline, policy);
    await projectPhase(
      context,
      state,
      context.globalArgs.statusIds.triage,
    );

    const attempt = state.attempt;
    const candidates =
      (await records(context, "candidate-main", CandidateSchema))
        .filter((record) => record.value.attempt === attempt);
    let candidateRecord = candidates.at(-1);
    if (
      candidateRecord &&
      state.currentCandidateVersion !== candidateRecord.version
    ) {
      state = {
        ...state,
        currentCandidateVersion: candidateRecord.version,
        updatedAt: now(),
      };
      await writeState(context, state);
    }
    if (!candidateRecord) {
      const authored = await persistAuthorResult(
        context,
        state,
        baseline,
        resolved.revision,
        resolved.vcs,
        policy,
      );
      state = authored.state;
      if (authored.stop) return { dataHandles: [] };
      if (!state.currentCandidateVersion || !authored.candidate) {
        throw new Error("Author completed without a persisted candidate");
      }
      candidateRecord = {
        version: state.currentCandidateVersion,
        value: authored.candidate,
      };
    } else {
      await persistCandidateArtifact(
        context,
        state,
        baseline,
        candidateRecord.value,
        candidateRecord.version,
      );
      await projectLifecycleComment(context, state);
    }

    while (state.completedReviewAttempts < 3) {
      const currentCandidate = candidateRecord;
      const reviews =
        (await records(context, "review-main", ReviewRecordSchema))
          .filter((record) =>
            record.value.attempt === attempt &&
            record.value.report.candidateVersion === currentCandidate.version
          );
      let reviewRecord = reviews.at(-1)?.value;
      if (!reviewRecord) {
        const reviewAttempt = state.completedReviewAttempts + 1;
        const report = await runReviewer({
          repoDir: context.repoDir,
          revision: resolved.revision,
          vcs: resolved.vcs,
          globalArgs: context.globalArgs,
          prompt: buildReviewerPrompt(
            baseline,
            currentCandidate.value,
            currentCandidate.version,
            policy,
          ),
        });
        if (
          report.attempt !== state.attempt ||
          report.candidateVersion !== currentCandidate.version
        ) {
          throw new AdapterError(
            "invalid_output",
            "Codex reviewer returned a report for the wrong attempt or candidate",
            false,
          );
        }
        reviewRecord = { attempt: state.attempt, reviewAttempt, report };
        await context.writeResource("review", "review-main", reviewRecord);
      }
      if (state.completedReviewAttempts < reviewRecord.reviewAttempt) {
        state = {
          ...state,
          completedReviewAttempts: reviewRecord.reviewAttempt,
          updatedAt: now(),
        };
        await writeState(context, state);
      }
      await persistReviewArtifact(context, state, baseline, reviewRecord);
      await projectLifecycleComment(context, state);

      if (reviewRecord.report.verdict === "approved") {
        await publishApproved(
          context,
          state,
          baseline,
          currentCandidate.value,
          currentCandidate.version,
        );
        return { dataHandles: [] };
      }
      if (state.completedReviewAttempts === 3) {
        const next = {
          ...state,
          phase: "needs_input" as const,
          updatedAt: now(),
        };
        await writeOutcome(context, {
          attempt: state.attempt,
          kind: "review_exhausted",
          summary: reviewRecord.report.summary,
          candidateVersion: currentCandidate.version,
          updatedAt: now(),
        });
        await writeState(context, next);
        await projectPhase(
          context,
          next,
          context.globalArgs.statusIds.triage,
        );
        return { dataHandles: [] };
      }

      const repaired = await persistAuthorResult(
        context,
        state,
        baseline,
        resolved.revision,
        resolved.vcs,
        policy,
        { candidate: currentCandidate.value, review: reviewRecord },
      );
      state = repaired.state;
      if (repaired.stop) return { dataHandles: [] };
      if (!state.currentCandidateVersion || !repaired.candidate) {
        throw new Error(
          "Author repair completed without a persisted candidate",
        );
      }
      candidateRecord = {
        version: state.currentCandidateVersion,
        value: repaired.candidate,
      };
    }
    return { dataHandles: [] };
  } catch (error) {
    if (error instanceof AdapterError && error.retryable) throw error;
    const persistedState = await readState(context);
    if (persistedState && persistedState.phase !== "planning") {
      context.logger.warning(
        "Preserving terminal semantic state after a later operation failed",
        { phase: persistedState.phase, error: String(error) },
      );
      throw error;
    }
    const failed = { ...state, phase: "failed" as const, updatedAt: now() };
    await writeOutcome(context, {
      attempt: state.attempt,
      kind: "failed",
      summary: error instanceof AdapterError
        ? `${error.kind}: ${error.message}`
        : String(error),
      updatedAt: now(),
    });
    await writeState(context, failed);
    await projectPhase(
      context,
      failed,
      context.globalArgs.statusIds.triage,
    );
    throw error;
  }
}

async function prepareMaterialization(
  args: { candidateVersion: number; planDigest: string; workflowRunId: string },
  context: Context,
): Promise<{ dataHandles: DataHandle[] }> {
  const state = await readState(context);
  if (!state) throw new Error("Planning state is missing");
  if (state.phase === "awaiting_approval") {
    if (state.activeMaterializationRunId !== args.workflowRunId) {
      throw new Error("Another materialization approval is active");
    }
    const existingRaw = await context.readResource(
      materializationName(args.workflowRunId),
    );
    if (existingRaw) {
      const existing = MaterializationSchema.parse(existingRaw);
      if (
        existing.candidateVersion === args.candidateVersion &&
        existing.planDigest === args.planDigest &&
        existing.workflowRunId === args.workflowRunId
      ) {
        const handle = await context.writeResource(
          "materialization",
          materializationName(args.workflowRunId),
          existing,
        );
        if (!await projectLifecycleComment(context, state, true)) {
          throw new AdapterError(
            "temporary",
            "The cumulative Linear comment is not confirmed",
            true,
          );
        }
        return { dataHandles: [handle] };
      }
    }
  }
  if (state.phase !== "decomposition_ready") {
    throw new Error("prepareMaterialization requires decomposition_ready");
  }
  const candidateRaw = await context.readResource(
    "candidate-main",
    args.candidateVersion,
  );
  if (!candidateRaw) {
    throw new Error(`Candidate version ${args.candidateVersion} was not found`);
  }
  const candidate = CandidateSchema.parse(candidateRaw);
  if (
    candidate.kind !== "decomposition_plan" ||
    candidate.attempt !== state.attempt
  ) {
    throw new Error(
      "Requested candidate is not the current attempt's decomposition",
    );
  }
  if (state.currentCandidateVersion !== args.candidateVersion) {
    throw new Error("Requested candidate is not current");
  }
  const digest = await sha256(candidate.plan);
  if (digest !== args.planDigest) {
    throw new Error("Decomposition digest mismatch");
  }
  let outcome = await readOutcome(context);
  if (
    ["implementation_ready", "decomposition_ready"].includes(state.phase) &&
    outcome &&
    !outcome.artifactUrl &&
    state.currentCandidateVersion
  ) {
    const candidateRaw = await context.readResource(
      "candidate-main",
      state.currentCandidateVersion,
    );
    const baseline = await readBaseline(context);
    if (candidateRaw && baseline) {
      await publishApproved(
        context,
        state,
        baseline,
        CandidateSchema.parse(candidateRaw),
        state.currentCandidateVersion,
      );
      outcome = await readOutcome(context);
    }
  }
  if (!outcome?.artifactUrl || outcome.planDigest !== digest) {
    throw new Error("Decomposition artifact is not confirmed in Linear");
  }
  const baseline = await readBaseline(context);
  if (!baseline || baseline.attempt !== state.attempt) {
    throw new Error("Ticket baseline missing");
  }
  const current = await linear(context).fetchIssue(
    state.issueIdentifier,
    state.attempt,
  );
  assertAllowedProject(context.globalArgs, current);
  if (!await projectLifecycleComment(context, state, true)) {
    throw new AdapterError(
      "temporary",
      "The approved decomposition is not confirmed in the cumulative Linear comment",
      true,
    );
  }
  const lifecycleEffectRaw = await context.readResource(
    "effect-lifecycle-comment",
  );
  const lifecycleCommentId = lifecycleEffectRaw
    ? EffectSchema.parse(lifecycleEffectRaw).remoteId
    : undefined;
  const materialization: Materialization = {
    attempt: state.attempt,
    candidateVersion: args.candidateVersion,
    planDigest: digest,
    workflowRunId: args.workflowRunId,
    issueIdentifier: state.issueIdentifier,
    artifactUrl: outcome.artifactUrl,
    childCount: candidate.plan.childTickets.length,
    ticketUpdatedAt: current.updatedAt,
    ticketChangedSincePlanning:
      await sha256(planningTicketContent(current, lifecycleCommentId)) !==
        await sha256(planningTicketContent(baseline, lifecycleCommentId)),
    childIds: {},
    childIdentifiers: {},
    relationKeys: [],
    preparedAt: now(),
  };
  const handle = await context.writeResource(
    "materialization",
    materializationName(args.workflowRunId),
    materialization,
  );
  const next = {
    ...state,
    phase: "awaiting_approval" as const,
    activeMaterializationRunId: args.workflowRunId,
    updatedAt: now(),
  };
  await writeState(context, next);
  if (!await projectLifecycleComment(context, next, true)) {
    throw new AdapterError(
      "temporary",
      "The materialization approval is not confirmed in the cumulative Linear comment",
      true,
    );
  }
  return { dataHandles: [handle] };
}

async function persistMaterialization(
  context: Context,
  value: Materialization,
): Promise<void> {
  await context.writeResource(
    "materialization",
    materializationName(value.workflowRunId),
    value,
  );
}

async function executeMaterialize(
  args: { candidateVersion: number; planDigest: string; workflowRunId: string },
  context: Context,
): Promise<{ dataHandles: DataHandle[] }> {
  let state = await readState(context);
  if (!state || !["awaiting_approval", "materializing"].includes(state.phase)) {
    throw new Error("materialize requires awaiting_approval or materializing");
  }
  if (state.activeMaterializationRunId !== args.workflowRunId) {
    throw new Error("Materialization is not bound to the active approval");
  }
  const materializationRaw = await context.readResource(
    materializationName(args.workflowRunId),
  );
  if (!materializationRaw) {
    throw new Error("Materialization gate payload missing");
  }
  let materialization = MaterializationSchema.parse(materializationRaw);
  if (
    materialization.candidateVersion !== args.candidateVersion ||
    materialization.planDigest !== args.planDigest ||
    materialization.workflowRunId !== args.workflowRunId
  ) {
    throw new Error(
      "Materialization arguments do not match the persisted gate payload",
    );
  }
  const candidateRaw = await context.readResource(
    "candidate-main",
    args.candidateVersion,
  );
  if (!candidateRaw) {
    throw new Error("Approved decomposition candidate missing");
  }
  const candidate = CandidateSchema.parse(candidateRaw);
  if (candidate.kind !== "decomposition_plan") {
    throw new Error("Candidate is not a decomposition");
  }
  if (await sha256(candidate.plan) !== args.planDigest) {
    throw new Error("Approved decomposition digest is no longer valid");
  }
  const baseline = await readBaseline(context);
  if (!baseline) throw new Error("Ticket baseline missing");
  const current = await linear(context).fetchIssue(
    state.issueIdentifier,
    state.attempt,
  );
  assertAllowedProject(context.globalArgs, current);
  if (
    state.phase === "awaiting_approval" &&
    current.updatedAt !== materialization.ticketUpdatedAt
  ) {
    const next = {
      ...state,
      phase: "decomposition_ready" as const,
      activeMaterializationRunId: undefined,
      updatedAt: now(),
    };
    await writeOutcome(context, {
      attempt: state.attempt,
      kind: "approval_stale",
      summary:
        "The Linear ticket changed while approval was pending; no children were created",
      candidateVersion: args.candidateVersion,
      planDigest: args.planDigest,
      materializationRunId: args.workflowRunId,
      updatedAt: now(),
    });
    await writeState(context, next);
    await projectLifecycleComment(context, next);
    return { dataHandles: [] };
  }

  if (state.phase === "awaiting_approval") {
    state = { ...state, phase: "materializing", updatedAt: now() };
    await writeState(context, state);
    await projectLifecycleComment(context, state);
  }
  try {
    const client = linear(context);
    for (
      const child of [...candidate.plan.childTickets].sort((a, b) =>
        a.ordinal - b.ordinal
      )
    ) {
      if (materialization.childIds[child.key]) continue;
      const marker = childMarker(
        context.definition.name,
        state.attempt,
        args.planDigest,
        child.key,
      );
      const expectedDescription = `${child.descriptionMarkdown}\n\n${marker}`;
      const parent = await client.fetchIssue(
        state.issueIdentifier,
        state.attempt,
      );
      assertAllowedProject(context.globalArgs, parent);
      const children = await client.listChildren(parent.id);
      const matches = children.filter((existing) =>
        existing.description.includes(marker)
      );
      if (matches.length > 1) {
        throw new AdapterError(
          "conflict",
          `Multiple children match marker ${marker}`,
          false,
        );
      }
      let childId: string;
      let childIdentifier: string;
      if (matches[0]) {
        if (matches[0].projectId !== parent.projectId) {
          throw new AdapterError(
            "authorization",
            `Existing child ${
              matches[0].identifier
            } is outside the configured project`,
            false,
          );
        }
        if (
          matches[0].title !== child.title ||
          matches[0].description !== expectedDescription
        ) {
          throw new AdapterError(
            "conflict",
            `Existing child ${
              matches[0].identifier
            } differs from decomposition key ${child.key}`,
            false,
          );
        }
        childId = matches[0].id;
        childIdentifier = matches[0].identifier;
      } else {
        const created = await client.createChild({
          teamId: parent.teamId,
          projectId: parent.projectId,
          parentId: parent.id,
          title: child.title,
          description: expectedDescription,
        });
        childId = created.id;
        childIdentifier = created.identifier;
      }
      materialization = {
        ...materialization,
        childIds: { ...materialization.childIds, [child.key]: childId },
        childIdentifiers: {
          ...materialization.childIdentifiers,
          [child.key]: childIdentifier,
        },
      };
      await persistMaterialization(context, materialization);
      state = { ...state, updatedAt: now() };
      await writeState(context, state);
      await projectLifecycleComment(context, state);
    }

    for (const blocked of candidate.plan.childTickets) {
      for (const dependency of blocked.dependencies) {
        const relationKey = `${dependency}->${blocked.key}`;
        if (materialization.relationKeys.includes(relationKey)) continue;
        const blockerId = materialization.childIds[dependency];
        const blockedId = materialization.childIds[blocked.key];
        if (!blockerId || !blockedId) {
          throw new Error(`Missing child ID for ${relationKey}`);
        }
        const relations = await client.listRelations(blockerId);
        const exists = relations.some((relation) =>
          relation.type === "blocks" &&
          relation.issueId === blockerId &&
          relation.relatedIssueId === blockedId
        );
        if (!exists) await client.createBlockingRelation(blockerId, blockedId);
        materialization = {
          ...materialization,
          relationKeys: [...materialization.relationKeys, relationKey],
        };
        await persistMaterialization(context, materialization);
        state = { ...state, updatedAt: now() };
        await writeState(context, state);
        await projectLifecycleComment(context, state);
      }
    }

    const next = {
      ...state,
      phase: "children_created" as const,
      activeMaterializationRunId: undefined,
      updatedAt: now(),
    };
    await writeOutcome(context, {
      attempt: state.attempt,
      kind: "children_created",
      summary: `Created or adopted ${
        Object.keys(materialization.childIds).length
      } child issues`,
      candidateVersion: args.candidateVersion,
      planDigest: args.planDigest,
      childIds: materialization.childIds,
      materializationRunId: args.workflowRunId,
      updatedAt: now(),
    });
    await writeState(context, next);
    await projectPhase(
      context,
      next,
      context.globalArgs.statusIds.inProgress,
    );
    return { dataHandles: [] };
  } catch (error) {
    if (error instanceof AdapterError && error.retryable) throw error;
    const failed = {
      ...state,
      phase: "failed" as const,
      activeMaterializationRunId: undefined,
      updatedAt: now(),
    };
    await writeOutcome(context, {
      attempt: state.attempt,
      kind: "failed",
      summary: error instanceof AdapterError
        ? `${error.kind}: ${error.message}`
        : String(error),
      candidateVersion: args.candidateVersion,
      planDigest: args.planDigest,
      childIds: materialization.childIds,
      materializationRunId: args.workflowRunId,
      updatedAt: now(),
    });
    await writeState(context, failed);
    await projectPhase(
      context,
      failed,
      context.globalArgs.statusIds.triage,
    );
    throw error;
  }
}

async function approvePlan(
  context: Context,
): Promise<{ dataHandles: DataHandle[] }> {
  const state = await readState(context);
  if (!state) throw new Error("Planning state is missing");
  let outcome = await readOutcome(context);
  if (state.phase === "implementation_approved") {
    if (outcome?.kind !== "implementation_approved") {
      throw new Error("Approved implementation outcome is missing");
    }
    await projectPhase(
      context,
      state,
      context.globalArgs.statusIds.inProgress,
      true,
    );
    return { dataHandles: [] };
  }
  if (state.phase !== "implementation_ready") {
    throw new Error("approvePlan requires implementation_ready");
  }
  if (
    !outcome || outcome.attempt !== state.attempt ||
    !["implementation_ready", "implementation_approved"].includes(
      outcome.kind,
    ) ||
    !outcome.candidateVersion ||
    !outcome.planDigest || !outcome.artifactUrl
  ) {
    throw new Error("Current implementation plan is not fully confirmed");
  }
  if (outcome.kind === "implementation_approved") {
    const next: PlanningState = {
      ...state,
      phase: "implementation_approved",
      updatedAt: outcome.updatedAt,
    };
    const stateHandle = await writeState(context, next);
    await projectPhase(
      context,
      next,
      context.globalArgs.statusIds.inProgress,
      true,
    );
    return { dataHandles: [stateHandle] };
  }
  const candidateRaw = await context.readResource(
    "candidate-main",
    outcome.candidateVersion,
  );
  if (!candidateRaw) {
    throw new Error("Approved implementation candidate is missing");
  }
  const candidate = CandidateSchema.parse(candidateRaw);
  if (
    candidate.kind !== "implementation_plan" ||
    candidate.attempt !== state.attempt ||
    await sha256(candidate.plan) !== outcome.planDigest
  ) {
    throw new Error(
      "Approved implementation candidate does not match the outcome",
    );
  }
  const baseline = await readBaseline(context);
  if (!baseline || baseline.attempt !== state.attempt) {
    throw new Error("Current planning baseline is missing");
  }
  const artifact = await persistCandidateArtifact(
    context,
    state,
    baseline,
    candidate,
    outcome.candidateVersion,
  );
  if (!artifact?.url) {
    throw new AdapterError(
      "temporary",
      "The implementation plan artifact is not confirmed in Linear",
      true,
    );
  }
  if (outcome.artifactUrl !== artifact.url) {
    outcome = { ...outcome, artifactUrl: artifact.url, updatedAt: now() };
    await writeOutcome(context, outcome);
  }
  if (!await projectLifecycleComment(context, state, true)) {
    throw new AdapterError(
      "temporary",
      "The implementation plan is not confirmed in the cumulative Linear comment",
      true,
    );
  }
  const approvedAt = now();
  const nextOutcome: Outcome = {
    ...outcome,
    kind: "implementation_approved",
    summary: "Implementation plan approved",
    updatedAt: approvedAt,
  };
  const next: PlanningState = {
    ...state,
    phase: "implementation_approved",
    updatedAt: approvedAt,
  };
  const outcomeHandle = await writeOutcome(context, nextOutcome);
  const stateHandle = await writeState(context, next);
  await projectPhase(
    context,
    next,
    context.globalArgs.statusIds.inProgress,
    true,
  );
  return { dataHandles: [outcomeHandle, stateHandle] };
}

async function cancelMaterialization(
  context: Context,
): Promise<{ dataHandles: DataHandle[] }> {
  const state = await readState(context);
  if (!state || state.phase !== "awaiting_approval") {
    throw new Error("cancelMaterialization requires awaiting_approval");
  }
  if (state.activeMaterializationRunId) {
    const raw = await context.readResource(
      materializationName(state.activeMaterializationRunId),
    );
    if (raw) {
      await persistMaterialization(context, {
        ...MaterializationSchema.parse(raw),
        cancelledAt: now(),
      });
    }
  }
  const next = {
    ...state,
    phase: "decomposition_ready" as const,
    activeMaterializationRunId: undefined,
    updatedAt: now(),
  };
  await writeState(context, next);
  await projectPhase(
    context,
    next,
    context.globalArgs.statusIds.triage,
  );
  return { dataHandles: [] };
}

async function syncLinear(
  context: Context,
): Promise<{ dataHandles: DataHandle[] }> {
  const state = await readState(context);
  if (!state) throw new Error("No planning state exists");
  const baseline = await readBaseline(context);
  if (!baseline || baseline.attempt !== state.attempt) {
    throw new Error("Current planning baseline is missing");
  }
  const current = await linear(context).fetchIssue(
    state.issueIdentifier,
    state.attempt,
  );
  assertAllowedProject(context.globalArgs, current);
  if (state.repositoryRevision) {
    const policy = await readPromptPolicy(context, state.attempt);
    if (
      !policy || policy.attempt !== state.attempt ||
      policy.digest !== state.promptPolicyDigest
    ) {
      throw new AdapterError(
        "conflict",
        "Current planning attempt has no matching frozen prompt policy",
        false,
      );
    }
    const snapshot = await persistInputSnapshot(
      context,
      state,
      baseline,
      policy,
    );
    if (!snapshot?.url) {
      throw new AdapterError(
        "temporary",
        "The input snapshot is not confirmed in Linear",
        true,
      );
    }
  }
  const candidates = (await records(context, "candidate-main", CandidateSchema))
    .filter((record) => record.value.attempt === state.attempt);
  for (const candidate of candidates) {
    const artifact = await persistCandidateArtifact(
      context,
      state,
      baseline,
      candidate.value,
      candidate.version,
    );
    if (!artifact?.url) {
      throw new AdapterError(
        "temporary",
        `Candidate artifact v${candidate.version} is not confirmed in Linear`,
        true,
      );
    }
  }
  const reviews = (await records(context, "review-main", ReviewRecordSchema))
    .map((record) => record.value)
    .filter((review) => review.attempt === state.attempt);
  for (const review of reviews) {
    const artifact = await persistReviewArtifact(
      context,
      state,
      baseline,
      review,
    );
    if (!artifact?.url) {
      throw new AdapterError(
        "temporary",
        `Review artifact ${review.reviewAttempt} is not confirmed in Linear`,
        true,
      );
    }
  }
  const outcome = await readOutcome(context);
  if (outcome?.kind === "needs_input" && outcome.blockingQuestions) {
    const artifact = await persistRequiredInputArtifact(
      context,
      state,
      baseline,
      outcome.summary,
      outcome.blockingQuestions,
    );
    if (!artifact?.url) {
      throw new AdapterError(
        "temporary",
        "The required-input artifact is not confirmed in Linear",
        true,
      );
    }
  }
  if (
    outcome && ["implementation_ready", "decomposition_ready"].includes(
      outcome.kind,
    ) &&
    !outcome.artifactUrl &&
    state.currentCandidateVersion
  ) {
    const candidateRaw = await context.readResource(
      "candidate-main",
      state.currentCandidateVersion,
    );
    if (candidateRaw) {
      await publishApproved(
        context,
        state,
        baseline,
        CandidateSchema.parse(candidateRaw),
        state.currentCandidateVersion,
      );
    }
  }
  const mapping: Partial<Record<PlanningState["phase"], string>> = {
    planning: context.globalArgs.statusIds.triage,
    needs_input: context.globalArgs.statusIds.triage,
    implementation_ready: context.globalArgs.statusIds.triage,
    implementation_approved: context.globalArgs.statusIds.inProgress,
    decomposition_ready: context.globalArgs.statusIds.triage,
    children_created: context.globalArgs.statusIds.inProgress,
    failed: context.globalArgs.statusIds.triage,
  };
  const status = mapping[state.phase];
  if (status) {
    await projectPhase(context, state, status, true);
  } else if (!await projectLifecycleComment(context, state, true)) {
    throw new AdapterError(
      "temporary",
      "The cumulative Linear comment is not confirmed",
      true,
    );
  }
  return { dataHandles: [] };
}

async function getOutcome(
  context: Context,
): Promise<{ dataHandles: DataHandle[] }> {
  const state = await readState(context);
  const outcome = await readOutcome(context);
  context.logger.info("Current planning outcome: {outcome}", {
    outcome: JSON.stringify({ state, outcome }),
  });
  return { dataHandles: [] };
}

export const model = {
  type: "@firma/feature-planning",
  version: "2026.07.24.8",
  globalArguments: GlobalArgsSchema,
  resources: {
    state: {
      description: "Coarse lifecycle state",
      schema: PlanningStateSchema,
      lifetime: "infinite" as const,
      garbageCollection: 20,
    },
    ticketBaseline: {
      description: "Normalized Linear ticket baseline",
      schema: TicketBaselineSchema,
      lifetime: "infinite" as const,
      garbageCollection: 20,
    },
    promptPolicy: {
      description:
        "Attempt-frozen repository planning and adversarial review policy",
      schema: PromptPolicySchema,
      lifetime: "infinite" as const,
      garbageCollection: 20,
    },
    candidate: {
      description: "Versioned implementation or decomposition candidate",
      schema: CandidateSchema,
      lifetime: "infinite" as const,
      garbageCollection: 50,
    },
    review: {
      description: "Fresh adversarial review bound to a candidate version",
      schema: ReviewRecordSchema,
      lifetime: "infinite" as const,
      garbageCollection: 50,
    },
    artifact: {
      description:
        "Uploaded immutable input, plan, and review artifact metadata",
      schema: ArtifactSchema,
      lifetime: "infinite" as const,
      garbageCollection: 100,
    },
    effects: {
      description: "Idempotent Linear projection effect",
      schema: EffectSchema,
      lifetime: "infinite" as const,
      garbageCollection: 20,
    },
    statusOwnership: {
      description: "Last Linear status confirmed as owned by this attempt",
      schema: StatusOwnershipSchema,
      lifetime: "infinite" as const,
      garbageCollection: 20,
    },
    materialization: {
      description: "Digest-bound approval payload and child reconciliation map",
      schema: MaterializationSchema,
      lifetime: "infinite" as const,
      garbageCollection: 20,
    },
    outcome: {
      description: "Latest typed planning or materialization outcome",
      schema: OutcomeSchema,
      lifetime: "infinite" as const,
      garbageCollection: 20,
    },
  },
  methods: {
    plan: {
      description: "Capture context and run the bounded author/reviewer loop",
      kind: "action" as const,
      arguments: z.object({
        ticketId: z.string().regex(/^[A-Za-z][A-Za-z0-9_]*-[1-9][0-9]*$/),
        repositoryRevision: z.string().optional(),
        triggerEventId: z.string().optional(),
      }),
      execute: executePlan,
    },
    approvePlan: {
      description: "Approve the current reviewed implementation plan",
      kind: "action" as const,
      arguments: z.object({}),
      execute: (_args: Record<string, never>, context: Context) =>
        approvePlan(context),
    },
    prepareMaterialization: {
      description:
        "Bind the exact approved decomposition to a manual approval run",
      kind: "action" as const,
      arguments: z.object({
        candidateVersion: z.number().int().positive(),
        planDigest: z.string().regex(/^[a-f0-9]{64}$/),
        workflowRunId: z.string().uuid(),
      }),
      execute: prepareMaterialization,
    },
    materialize: {
      description: "Reconcile and create child issues after approval",
      kind: "action" as const,
      arguments: z.object({
        candidateVersion: z.number().int().positive(),
        planDigest: z.string().regex(/^[a-f0-9]{64}$/),
        workflowRunId: z.string().uuid(),
      }),
      execute: executeMaterialize,
    },
    cancelMaterialization: {
      description: "Cancel a rejected or abandoned materialization approval",
      kind: "action" as const,
      arguments: z.object({}),
      execute: (_args: Record<string, never>, context: Context) =>
        cancelMaterialization(context),
    },
    syncLinear: {
      description:
        "Retry convergent Linear projections without changing semantic state",
      kind: "action" as const,
      arguments: z.object({}),
      execute: (_args: Record<string, never>, context: Context) =>
        syncLinear(context),
    },
    getOutcome: {
      description:
        "Return the current state and latest outcome without external effects",
      kind: "read" as const,
      arguments: z.object({}),
      execute: (_args: Record<string, never>, context: Context) =>
        getOutcome(context),
    },
  },
};
