import { z } from "npm:zod@4.3.6";

export const PhaseSchema = z.enum([
  "planning",
  "needs_input",
  "implementation_ready",
  "implementation_approved",
  "decomposition_ready",
  "awaiting_approval",
  "materializing",
  "children_created",
  "failed",
]);

export type Phase = z.infer<typeof PhaseSchema>;

export const StatusIdsSchema = z.strictObject({
  triage: z.string().min(1),
  inProgress: z.string().min(1),
});

const RepositoryCommitUrlPrefixSchema = z.string().url().refine(
  (value) => value.endsWith("/"),
  "Repository commit URL prefix must end with a slash",
);
const WorkflowNameSchema = z.string().regex(
  /^@[a-z0-9][a-z0-9-]*\/[a-z0-9][a-z0-9-]*$/,
);

export const GlobalArgsSchema = z.strictObject({
  linearApiKey: z.string().min(1).meta({ sensitive: true }),
  linearApiUrl: z.string().url().default("https://api.linear.app/graphql"),
  allowedProjectIdsCsv: z.string().min(1),
  statusIds: StatusIdsSchema,
  allowedIntakeStatusIdsCsv: z.string().min(1),
  repositoryDisplayName: z.string().min(1),
  repositoryCommitUrlPrefix: RepositoryCommitUrlPrefixSchema,
  planningWorkflowName: WorkflowNameSchema,
  materializationWorkflowName: WorkflowNameSchema,
  codexBinary: z.string().min(1).default("codex"),
  codexModel: z.string().min(1).optional(),
  codexTimeoutSeconds: z.number().int().min(60).max(7200).default(1800),
});

export type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

export const PlanningStateSchema = z.strictObject({
  issueIdentifier: z.string().min(1),
  attempt: z.number().int().positive(),
  planningRunId: z.string().uuid(),
  startedAt: z.string().datetime(),
  phase: PhaseSchema,
  repositoryRevision: z.string().min(1).optional(),
  promptPolicyDigest: z.string().regex(/^[a-f0-9]{64}$/).optional(),
  currentCandidateVersion: z.number().int().positive().optional(),
  activeMaterializationRunId: z.string().uuid().optional(),
  completedReviewAttempts: z.number().int().min(0).max(3),
  triggerEventId: z.string().min(1).optional(),
  initialStatusId: z.string().min(1),
  updatedAt: z.string().datetime(),
});

export type PlanningState = z.infer<typeof PlanningStateSchema>;

export const PromptPolicySchema = z.strictObject({
  attempt: z.number().int().positive(),
  repositoryRevision: z.string().min(1),
  contractVersion: z.literal("1"),
  repositoryDisplayName: z.string().min(1),
  repositoryCommitUrlPrefix: RepositoryCommitUrlPrefixSchema,
  planningWorkflowName: WorkflowNameSchema,
  materializationWorkflowName: WorkflowNameSchema,
  planningConventionsPath: z.literal(
    "agent-constraints/planning-conventions.md",
  ),
  planningConventions: z.string().min(1).max(32_768),
  adversarialDimensionsPath: z.literal(
    "agent-constraints/adversarial-dimensions.md",
  ),
  adversarialDimensions: z.string().min(1).max(32_768),
  digest: z.string().regex(/^[a-f0-9]{64}$/),
  capturedAt: z.string().datetime(),
});

export type PromptPolicy = z.infer<typeof PromptPolicySchema>;

const CommentSchema = z.strictObject({
  id: z.string().min(1),
  body: z.string(),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
});

export const TicketBaselineSchema = z.strictObject({
  attempt: z.number().int().positive(),
  id: z.string().min(1),
  identifier: z.string().min(1),
  title: z.string().min(1),
  description: z.string(),
  url: z.string().url(),
  updatedAt: z.string().datetime(),
  teamId: z.string().min(1),
  projectId: z.string().min(1).nullable(),
  projectName: z.string().min(1).nullable(),
  stateId: z.string().min(1),
  stateName: z.string().min(1),
  comments: z.array(CommentSchema),
  capturedAt: z.string().datetime(),
});

export type TicketBaseline = z.infer<typeof TicketBaselineSchema>;

const PlanPhaseSchema = z.strictObject({
  title: z.string().min(1),
  changes: z.array(z.string().min(1)).min(1),
  codeTouchpoints: z.array(z.string().min(1)).min(1),
  tests: z.array(z.string().min(1)),
  documentation: z.array(z.string().min(1)),
  gate: z.array(z.string().min(1)).min(1),
});

export const PlanSchema = z.strictObject({
  attempt: z.number().int().positive(),
  ticket: z.string().min(1),
  repositoryRevision: z.string().min(1),
  objective: z.string().min(1),
  currentBehavior: z.array(z.string().min(1)),
  scope: z.array(z.string().min(1)).min(1),
  nonGoals: z.array(z.string().min(1)),
  assumptions: z.array(z.string().min(1)),
  invariants: z.array(z.string().min(1)),
  design: z.string().min(1),
  phases: z.array(PlanPhaseSchema).min(1),
  risks: z.array(z.string().min(1)),
  acceptanceCriteria: z.array(z.string().min(1)).min(1),
  verificationCommands: z.array(z.string().min(1)).min(1),
});

export type Plan = z.infer<typeof PlanSchema>;

export const ChildTicketSchema = z.strictObject({
  key: z.string().regex(/^[a-z][a-z0-9-]*$/),
  ordinal: z.number().int().positive(),
  title: z.string().min(1),
  descriptionMarkdown: z.string().min(1),
  acceptanceCriteria: z.array(z.string().min(1)).min(1),
  dependencies: z.array(z.string().min(1)),
});

export const DecompositionSchema = z.strictObject({
  attempt: z.number().int().positive(),
  ticket: z.string().min(1),
  repositoryRevision: z.string().min(1),
  objective: z.string().min(1),
  whyDecompositionIsRequired: z.array(z.string().min(1)).min(1),
  sharedConstraints: z.array(z.string().min(1)),
  childTickets: z.array(ChildTicketSchema).min(2),
  integrationStrategy: z.array(z.string().min(1)).min(1),
  overallAcceptanceCriteria: z.array(z.string().min(1)).min(1),
}).superRefine((value, context) => {
  const keys = new Set<string>();
  const ordinals = new Set<number>();
  for (const child of value.childTickets) {
    if (keys.has(child.key)) {
      context.addIssue({
        code: "custom",
        message: `Duplicate child key: ${child.key}`,
        path: ["childTickets"],
      });
    }
    if (ordinals.has(child.ordinal)) {
      context.addIssue({
        code: "custom",
        message: `Duplicate child ordinal: ${child.ordinal}`,
        path: ["childTickets"],
      });
    }
    keys.add(child.key);
    ordinals.add(child.ordinal);
  }

  const visiting = new Set<string>();
  const visited = new Set<string>();
  const dependencies = new Map(
    value.childTickets.map((child) => [child.key, child.dependencies]),
  );
  const visit = (key: string): boolean => {
    if (visiting.has(key)) return true;
    if (visited.has(key)) return false;
    visiting.add(key);
    for (const dependency of dependencies.get(key) ?? []) {
      if (!keys.has(dependency)) {
        context.addIssue({
          code: "custom",
          message: `Unknown child dependency: ${dependency}`,
          path: ["childTickets"],
        });
        continue;
      }
      if (visit(dependency)) return true;
    }
    visiting.delete(key);
    visited.add(key);
    return false;
  };
  if ([...keys].some(visit)) {
    context.addIssue({
      code: "custom",
      message: "Child dependencies must form a DAG",
      path: ["childTickets"],
    });
  }
});

export type Decomposition = z.infer<typeof DecompositionSchema>;

export const NeedsInputSchema = z.strictObject({
  kind: z.literal("needs_input"),
  summary: z.string().min(1),
  blockingQuestions: z.array(z.strictObject({
    question: z.string().min(1),
    whyBlocking: z.string().min(1),
  })).min(1),
});

export const AuthorResultSchema = z.discriminatedUnion("kind", [
  NeedsInputSchema,
  z.strictObject({
    kind: z.literal("implementation_plan"),
    plan: PlanSchema,
  }),
  z.strictObject({
    kind: z.literal("decomposition_plan"),
    plan: DecompositionSchema,
  }),
]);

export type AuthorResult = z.infer<typeof AuthorResultSchema>;

export const CandidateSchema = z.discriminatedUnion("kind", [
  z.strictObject({
    kind: z.literal("implementation_plan"),
    attempt: z.number().int().positive(),
    authorRound: z.number().int().positive(),
    plan: PlanSchema,
  }),
  z.strictObject({
    kind: z.literal("decomposition_plan"),
    attempt: z.number().int().positive(),
    authorRound: z.number().int().positive(),
    plan: DecompositionSchema,
  }),
]);

export type Candidate = z.infer<typeof CandidateSchema>;

export const ReviewReportSchema = z.strictObject({
  attempt: z.number().int().positive(),
  candidateVersion: z.number().int().positive(),
  verdict: z.enum(["approved", "changes_required"]),
  summary: z.string().min(1),
  findings: z.array(z.strictObject({
    id: z.string().min(1),
    severity: z.enum(["blocking", "high", "medium", "low"]),
    category: z.string().min(1),
    location: z.string().min(1),
    problem: z.string().min(1),
    requiredChange: z.string().min(1),
  })),
  residualRisks: z.array(z.string().min(1)),
}).superRefine((value, context) => {
  if (value.verdict === "approved" && value.findings.length > 0) {
    context.addIssue({
      code: "custom",
      message: "Approved reviews cannot contain actionable findings",
      path: ["findings"],
    });
  }
  if (value.verdict === "changes_required" && value.findings.length === 0) {
    context.addIssue({
      code: "custom",
      message: "Changes-required reviews must contain a finding",
      path: ["findings"],
    });
  }
});

export type ReviewReport = z.infer<typeof ReviewReportSchema>;

export const ReviewRecordSchema = z.strictObject({
  attempt: z.number().int().positive(),
  reviewAttempt: z.number().int().min(1).max(3),
  report: ReviewReportSchema,
});

export type ReviewRecord = z.infer<typeof ReviewRecordSchema>;

const ArtifactBaseSchema = z.strictObject({
  attempt: z.number().int().positive(),
  filename: z.string().min(1),
  contentType: z.enum(["application/json", "text/markdown"]),
  digest: z.string().regex(/^[a-f0-9]{64}$/),
  status: z.enum(["pending", "confirmed"]),
  url: z.string().url().optional(),
  createdAt: z.string().datetime(),
  uploadedAt: z.string().datetime().optional(),
});

export const ArtifactSchema = z.discriminatedUnion("kind", [
  ArtifactBaseSchema.extend({ kind: z.literal("input_snapshot") }),
  ArtifactBaseSchema.extend({ kind: z.literal("required_input") }),
  ArtifactBaseSchema.extend({
    kind: z.literal("candidate"),
    candidateVersion: z.number().int().positive(),
  }),
  ArtifactBaseSchema.extend({
    kind: z.literal("review"),
    candidateVersion: z.number().int().positive(),
    reviewAttempt: z.number().int().min(1).max(3),
  }),
]).superRefine((artifact, context) => {
  if (artifact.status === "confirmed") {
    if (!artifact.url) {
      context.addIssue({
        code: "custom",
        message: "Confirmed artifacts require an upload URL",
        path: ["url"],
      });
    }
    if (!artifact.uploadedAt) {
      context.addIssue({
        code: "custom",
        message: "Confirmed artifacts require an upload timestamp",
        path: ["uploadedAt"],
      });
    }
  } else if (artifact.url || artifact.uploadedAt) {
    context.addIssue({
      code: "custom",
      message: "Pending artifacts cannot contain confirmed upload metadata",
      path: artifact.url ? ["url"] : ["uploadedAt"],
    });
  }
});

export type Artifact = z.infer<typeof ArtifactSchema>;

export const EffectSchema = z.strictObject({
  key: z.string().min(1),
  attempt: z.number().int().positive(),
  inputDigest: z.string().regex(/^[a-f0-9]{64}$/),
  status: z.enum(["pending", "confirmed", "failed"]),
  remoteId: z.string().min(1).optional(),
  attempts: z.number().int().min(0),
  lastError: z.string().min(1).optional(),
  updatedAt: z.string().datetime(),
});

export type Effect = z.infer<typeof EffectSchema>;

export const StatusOwnershipSchema = z.strictObject({
  attempt: z.number().int().positive(),
  statusId: z.string().min(1),
  updatedAt: z.string().datetime(),
});

export const MaterializationSchema = z.strictObject({
  attempt: z.number().int().positive(),
  candidateVersion: z.number().int().positive(),
  planDigest: z.string().regex(/^[a-f0-9]{64}$/),
  workflowRunId: z.string().uuid(),
  issueIdentifier: z.string().min(1),
  artifactUrl: z.string().url(),
  childCount: z.number().int().positive(),
  ticketUpdatedAt: z.string().datetime(),
  ticketChangedSincePlanning: z.boolean(),
  childIds: z.record(z.string(), z.string().min(1)),
  childIdentifiers: z.record(z.string(), z.string().min(1)),
  relationKeys: z.array(z.string().min(1)),
  preparedAt: z.string().datetime(),
  cancelledAt: z.string().datetime().optional(),
}).superRefine((materialization, context) => {
  const childKeys = Object.keys(materialization.childIds).sort();
  const identifierKeys = Object.keys(materialization.childIdentifiers).sort();
  if (childKeys.join("\0") !== identifierKeys.join("\0")) {
    context.addIssue({
      code: "custom",
      message: "Child IDs and identifiers must contain the same keys",
      path: ["childIdentifiers"],
    });
  }
});

export type Materialization = z.infer<typeof MaterializationSchema>;

export const OutcomeSchema = z.strictObject({
  attempt: z.number().int().positive(),
  kind: z.enum([
    "needs_input",
    "review_exhausted",
    "implementation_ready",
    "implementation_approved",
    "decomposition_ready",
    "approval_stale",
    "children_created",
    "failed",
  ]),
  summary: z.string().min(1),
  candidateVersion: z.number().int().positive().optional(),
  planDigest: z.string().regex(/^[a-f0-9]{64}$/).optional(),
  artifactUrl: z.string().url().optional(),
  blockingQuestions: NeedsInputSchema.shape.blockingQuestions.optional(),
  childIds: z.record(z.string(), z.string().min(1)).optional(),
  materializationRunId: z.string().uuid().optional(),
  updatedAt: z.string().datetime(),
});

export type Outcome = z.infer<typeof OutcomeSchema>;
