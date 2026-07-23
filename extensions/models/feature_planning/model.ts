import { z } from "npm:zod@4.3.6";
import {
  AdapterError,
  LinearClient,
  resolveRepositoryRevision,
  runAuthor,
  runReviewer,
} from "./adapters.ts";
import {
  buildAuthorPrompt,
  buildReviewerPrompt,
  childMarker,
  lifecycleMarker,
  planningTicketContent,
  renderDecomposition,
  renderPlan,
  sha256,
} from "./helpers.ts";
import {
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

async function records<T>(
  context: Context,
  instanceName: string,
  schema: z.ZodType<T>,
): Promise<Array<{ version: number; value: T }>> {
  const metadata = await context.dataRepository.findAllForModel(
    context.modelType,
    context.modelId,
  );
  const versions = [
    ...new Set(
      metadata.filter((entry) => entry.name === instanceName)
        .map((entry) => entry.version),
    ),
  ].sort((left, right) => left - right);
  const output: Array<{ version: number; value: T }> = [];
  for (const version of versions) {
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
): Promise<string | undefined> {
  const instanceName = `effect-${key}`;
  const inputDigest = await sha256({ attempt: state.attempt, input });
  const existingRaw = await context.readResource(instanceName);
  if (existingRaw) {
    const existing = EffectSchema.parse(existingRaw);
    if (
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

async function publishAttachmentEffect(
  context: Context,
  state: PlanningState,
  key: string,
  input: {
    issueId: string;
    filename: string;
    markdown: string;
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
        "Linear issue identity changed before attachment projection",
        false,
      );
    }
    if (!assetUrl) {
      assetUrl = await client.uploadMarkdownAsset(
        input.filename,
        input.markdown,
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
    await client.createAttachment(
      input.issueId,
      input.filename,
      assetUrl,
      input.digest,
      state.attempt,
    );
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
    context.logger.warning("Linear attachment projection failed", {
      key,
      error: String(error),
    });
    return undefined;
  }
}

function allowedIntakeStatusIds(globalArgs: GlobalArgs): Set<string> {
  return new Set([
    ...globalArgs.allowedIntakeStatusIds,
    ...globalArgs.allowedIntakeStatusIdsCsv.split(",").map((value) =>
      value.trim()
    )
      .filter(Boolean),
  ]);
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

async function projectStatus(
  context: Context,
  state: PlanningState,
  targetStatusId: string,
): Promise<void> {
  const client = linear(context);
  await runEffect(
    context,
    state,
    `status-${targetStatusId}`,
    { issueIdentifier: state.issueIdentifier, targetStatusId },
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
        return current.stateId;
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
  );
}

async function projectLifecycleComment(
  context: Context,
  state: PlanningState,
  body: string,
): Promise<void> {
  const client = linear(context);
  const marker = lifecycleMarker(context.definition.name, state.attempt);
  await runEffect(
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
  );
}

async function projectPhase(
  context: Context,
  state: PlanningState,
  statusId: string,
  summary: string,
): Promise<void> {
  await projectStatus(context, state, statusId);
  await projectLifecycleComment(
    context,
    state,
    [
      `Phase: ${state.phase}`,
      `Attempt: ${state.attempt}`,
      `Completed reviews: ${state.completedReviewAttempts}/3`,
      "",
      summary,
    ].join("\n"),
  );
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
      previous
        ? { candidate: previous.candidate, review: previous.review.report }
        : undefined,
    ),
  });
  if (result.kind === "needs_input") {
    const next = { ...state, phase: "needs_input" as const, updatedAt: now() };
    await writeOutcome(context, {
      attempt: state.attempt,
      kind: "needs_input",
      summary: result.summary,
      blockingQuestions: result.blockingQuestions,
      updatedAt: now(),
    });
    await writeState(context, next);
    await projectPhase(
      context,
      next,
      context.globalArgs.statusIds.needsInput,
      `${result.summary}\n\n${
        result.blockingQuestions.map((question) =>
          `- ${question.question}: ${question.whyBlocking}`
        ).join("\n")
      }`,
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
  return { state: next, candidate, stop: false };
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
  const filename = implementation
    ? `${state.issueIdentifier}-implementation-plan.md`
    : `${state.issueIdentifier}-decomposition-plan.md`;
  const markdown = implementation
    ? renderPlan(candidate.plan, digest)
    : renderDecomposition(candidate.plan, digest);
  const attachmentUrl = await publishAttachmentEffect(
    context,
    state,
    `attachment-candidate-${candidateVersion}`,
    { issueId: baseline.id, filename, markdown, digest },
  );
  if (!attachmentUrl) {
    context.logger.warning(
      "Approved plan is persisted but Linear attachment is pending",
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
    attachmentUrl,
    updatedAt: now(),
  };
  await writeOutcome(context, outcome);
  await writeState(context, next);
  await projectPhase(
    context,
    next,
    implementation
      ? context.globalArgs.statusIds.readyForImplementation
      : context.globalArgs.statusIds.awaitingApproval,
    implementation
      ? `Reviewed implementation plan v${candidateVersion}: ${
        attachmentUrl ?? "Linear attachment pending"
      }`
      : `Reviewed decomposition v${candidateVersion}, digest ${digest}: ${
        attachmentUrl ?? "Linear attachment pending"
      }`,
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
    context.logger.info("Ignoring duplicate planning trigger", {
      triggerEventId: args.triggerEventId,
    });
    return { dataHandles: [] };
  }
  if (state && ["awaiting_approval", "materializing"].includes(state.phase)) {
    throw new Error(`plan cannot run while phase is ${state.phase}`);
  }

  if (!state || state.phase !== "planning") {
    state = {
      issueIdentifier: requestedTicket,
      attempt: (state?.attempt ?? 0) + 1,
      phase: "planning",
      completedReviewAttempts: 0,
      triggerEventId: args.triggerEventId || undefined,
      updatedAt: now(),
    };
    await writeState(context, state);
  }

  const persistedOutcome = await readOutcome(context);
  if (persistedOutcome?.attempt === state.attempt) {
    const outcomePhase = {
      needs_input: "needs_input",
      review_exhausted: "needs_input",
      implementation_ready: "implementation_ready",
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
      return { dataHandles: [] };
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
    await projectPhase(
      context,
      state,
      context.globalArgs.statusIds.planning,
      `Planning against repository revision ${resolved.revision}`,
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
          context.globalArgs.statusIds.needsInput,
          `Three reviews completed; human action is required.\n\n${reviewRecord.report.summary}`,
        );
        return { dataHandles: [] };
      }

      const repaired = await persistAuthorResult(
        context,
        state,
        baseline,
        resolved.revision,
        resolved.vcs,
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
      context.globalArgs.statusIds.planningFailed,
      "Planning failed. Inspect the Swamp outcome and method report for a redacted diagnostic.",
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
    !outcome.attachmentUrl &&
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
  if (!outcome?.attachmentUrl || outcome.planDigest !== digest) {
    throw new Error("Decomposition attachment is not confirmed in Linear");
  }
  const baseline = await readBaseline(context);
  if (!baseline || baseline.attempt !== state.attempt) {
    throw new Error("Ticket baseline missing");
  }
  assertAllowedProject(context.globalArgs, baseline);
  const current = await linear(context).fetchIssue(
    state.issueIdentifier,
    state.attempt,
  );
  assertAllowedProject(context.globalArgs, current);
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
    attachmentUrl: outcome.attachmentUrl,
    childCount: candidate.plan.childTickets.length,
    ticketUpdatedAt: current.updatedAt,
    ticketChangedSincePlanning:
      await sha256(planningTicketContent(current, lifecycleCommentId)) !==
        await sha256(planningTicketContent(baseline, lifecycleCommentId)),
    childIds: {},
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
  await projectLifecycleComment(
    context,
    next,
    `Awaiting approval for decomposition v${args.candidateVersion}, digest ${digest}. Ticket changed since planning: ${materialization.ticketChangedSincePlanning}.`,
  );
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
  assertAllowedProject(context.globalArgs, baseline);
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
      updatedAt: now(),
    });
    await writeState(context, next);
    await projectLifecycleComment(
      context,
      next,
      "Approval became stale because the Linear ticket changed. Launch a fresh materialization workflow.",
    );
    return { dataHandles: [] };
  }

  if (state.phase === "awaiting_approval") {
    state = { ...state, phase: "materializing", updatedAt: now() };
    await writeState(context, state);
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
      const children = await client.listChildren(baseline.id);
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
      if (matches[0]) {
        if (matches[0].projectId !== baseline.projectId) {
          throw new AdapterError(
            "authorization",
            `Existing child ${matches[0].identifier} is outside the configured project`,
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
      } else {
        const created = await client.createChild({
          teamId: baseline.teamId,
          projectId: baseline.projectId,
          parentId: baseline.id,
          title: child.title,
          description: expectedDescription,
        });
        childId = created.id;
      }
      materialization = {
        ...materialization,
        childIds: { ...materialization.childIds, [child.key]: childId },
      };
      await persistMaterialization(context, materialization);
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
      updatedAt: now(),
    });
    await writeState(context, next);
    await projectPhase(
      context,
      next,
      context.globalArgs.statusIds.planned,
      `Children reconciled:\n${
        Object.entries(materialization.childIds).map(([key, id]) =>
          `- ${key}: ${id}`
        ).join("\n")
      }`,
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
      updatedAt: now(),
    });
    await writeState(context, failed);
    await projectPhase(
      context,
      failed,
      context.globalArgs.statusIds.planningFailed,
      "Child materialization failed. Existing children were preserved; inspect the Swamp outcome before retrying.",
    );
    throw error;
  }
}

async function cancelMaterialization(
  context: Context,
): Promise<{ dataHandles: DataHandle[] }> {
  const state = await readState(context);
  if (!state || state.phase !== "awaiting_approval") {
    throw new Error("cancelMaterialization requires awaiting_approval");
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
    context.globalArgs.statusIds.needsInput,
    "Materialization approval was rejected or abandoned. Re-plan or launch a corrected approval run.",
  );
  return { dataHandles: [] };
}

async function syncLinear(
  context: Context,
): Promise<{ dataHandles: DataHandle[] }> {
  const state = await readState(context);
  if (!state) throw new Error("No planning state exists");
  let outcome = await readOutcome(context);
  if (
    ["implementation_ready", "decomposition_ready"].includes(state.phase) &&
    outcome &&
    !outcome.attachmentUrl &&
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
  const mapping: Partial<Record<PlanningState["phase"], string>> = {
    planning: context.globalArgs.statusIds.planning,
    needs_input: context.globalArgs.statusIds.needsInput,
    implementation_ready: context.globalArgs.statusIds.readyForImplementation,
    decomposition_ready: context.globalArgs.statusIds.awaitingApproval,
    children_created: context.globalArgs.statusIds.planned,
    failed: context.globalArgs.statusIds.planningFailed,
  };
  const status = mapping[state.phase];
  if (status) {
    await projectPhase(
      context,
      state,
      status,
      outcome?.summary ?? `Reconciled Linear projection for ${state.phase}`,
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
  type: "@openfirma/feature-planning",
  version: "2026.07.23.5",
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
