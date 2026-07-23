import { z } from "npm:zod@4.3.6";

export const PhaseSchema = z.enum([
  "planning",
  "needs_input",
  "implementation_ready",
  "decomposition_ready",
  "awaiting_approval",
  "materializing",
  "children_created",
  "failed",
]);

export type Phase = z.infer<typeof PhaseSchema>;

export const StatusIdsSchema = z.strictObject({
  planning: z.string().min(1).meta({ sensitive: true }),
  needsInput: z.string().min(1).meta({ sensitive: true }),
  planningFailed: z.string().min(1).meta({ sensitive: true }),
  awaitingApproval: z.string().min(1).meta({ sensitive: true }),
  readyForImplementation: z.string().min(1).meta({ sensitive: true }),
  planned: z.string().min(1).meta({ sensitive: true }),
});

export const GlobalArgsSchema = z.strictObject({
  linearApiKey: z.string().min(1).meta({ sensitive: true }),
  linearApiUrl: z.string().url().default("https://api.linear.app/graphql"),
  allowedProjectIdsCsv: z.string().min(1).meta({ sensitive: true }),
  statusIds: StatusIdsSchema,
  allowedIntakeStatusIds: z.array(z.string().min(1)).default([]),
  allowedIntakeStatusIdsCsv: z.string().default("").meta({ sensitive: true }),
  codexBinary: z.string().min(1).default("codex"),
  codexModel: z.string().min(1).optional(),
  codexTimeoutSeconds: z.number().int().min(60).max(7200).default(1800),
});

export type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

export const PlanningStateSchema = z.strictObject({
  issueIdentifier: z.string().min(1),
  attempt: z.number().int().positive(),
  phase: PhaseSchema,
  repositoryRevision: z.string().min(1).optional(),
  currentCandidateVersion: z.number().int().positive().optional(),
  activeMaterializationRunId: z.string().uuid().optional(),
  completedReviewAttempts: z.number().int().min(0).max(3),
  triggerEventId: z.string().min(1).optional(),
  initialStatusId: z.string().min(1).optional(),
  updatedAt: z.string().datetime(),
});

export type PlanningState = z.infer<typeof PlanningStateSchema>;

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
  attachmentUrl: z.string().url(),
  childCount: z.number().int().positive(),
  ticketUpdatedAt: z.string().datetime(),
  ticketChangedSincePlanning: z.boolean(),
  childIds: z.record(z.string(), z.string().min(1)),
  relationKeys: z.array(z.string().min(1)),
  preparedAt: z.string().datetime(),
});

export type Materialization = z.infer<typeof MaterializationSchema>;

export const OutcomeSchema = z.strictObject({
  attempt: z.number().int().positive(),
  kind: z.enum([
    "needs_input",
    "review_exhausted",
    "implementation_ready",
    "decomposition_ready",
    "approval_stale",
    "children_created",
    "failed",
  ]),
  summary: z.string().min(1),
  candidateVersion: z.number().int().positive().optional(),
  planDigest: z.string().regex(/^[a-f0-9]{64}$/).optional(),
  attachmentUrl: z.string().url().optional(),
  blockingQuestions: NeedsInputSchema.shape.blockingQuestions.optional(),
  childIds: z.record(z.string(), z.string().min(1)).optional(),
  updatedAt: z.string().datetime(),
});

export type Outcome = z.infer<typeof OutcomeSchema>;
