import {
  assert,
  assertEquals,
  assertMatch,
  assertRejects,
  assertStringIncludes,
} from "jsr:@std/assert@1.0.19";
import {
  archiveRepository,
  codexJsonSchema,
  codexEnvironment,
  codexPermissionArguments,
  LinearClient,
  resolveRepositoryRevision,
} from "./adapters.ts";
import {
  buildAuthorPrompt,
  buildReviewerPrompt,
  canonicalJson,
  childMarker,
  planningRunMarker,
  planningTicketContent,
  renderDecomposition,
  renderReview,
  sha256,
} from "./helpers.ts";
import {
  assertAllowedProject,
  model,
  projectPhase,
  projectStatus,
  records,
  renderPlanningComment,
} from "./model.ts";
import {
  type Artifact,
  type Candidate,
  CandidateSchema,
  DecompositionSchema,
  type GlobalArgs,
  GlobalArgsSchema,
  MaterializationSchema,
  PlanningStateSchema,
  type ReviewRecord,
  type ReviewReport,
  ReviewReportSchema,
  type TicketBaseline,
  TicketBaselineSchema,
  ArtifactSchema,
} from "./schemas.ts";

const baseline: TicketBaseline = {
  attempt: 1,
  id: "issue-id",
  identifier: "FIR-123",
  title: "Plan feature",
  description: "Ticket body",
  url: "https://linear.app/openfirma/issue/FIR-123",
  updatedAt: "2026-07-23T12:00:00.000Z",
  teamId: "team-id",
  projectId: "project-id",
  projectName: "Automation Experiments",
  stateId: "state-id",
  stateName: "Backlog",
  comments: [],
  capturedAt: "2026-07-23T12:01:00.000Z",
};

const globalArgs: GlobalArgs = {
  linearApiKey: "test-key",
  linearApiUrl: "https://api.linear.app/graphql",
  allowedProjectIdsCsv: "project-id, other-project-id",
  statusIds: {
    triage: "state-id",
    inProgress: "in-progress",
  },
  allowedIntakeStatusIdsCsv: "state-id",
  codexBinary: "codex",
  codexTimeoutSeconds: 1800,
};

Deno.test("project allowlist rejects unassigned and out-of-scope tickets", async () => {
  assertAllowedProject(globalArgs, baseline);
  await assertRejects(
    async () =>
      assertAllowedProject(globalArgs, { ...baseline, projectId: null }),
    Error,
    "outside the configured project allowlist",
  );
  await assertRejects(
    async () =>
      assertAllowedProject(globalArgs, {
        ...baseline,
        projectId: "different-project",
      }),
    Error,
    "outside the configured project allowlist",
  );
});

Deno.test("Codex output schema uses supported union keywords", () => {
  const schema = codexJsonSchema(DecompositionSchema.or(ReviewReportSchema));
  assertEquals(schema.type, "object");
  assertEquals(schema.required, ["result"]);
  const serialized = JSON.stringify(schema);
  assertStringIncludes(serialized, '"anyOf"');
  assertEquals(serialized.includes('"oneOf"'), false);
});

const candidate: Candidate = {
  kind: "implementation_plan",
  attempt: 1,
  authorRound: 1,
  plan: {
    attempt: 1,
    ticket: "FIR-123",
    repositoryRevision: "abc123",
    objective: "Implement the feature",
    currentBehavior: ["No feature exists"],
    scope: ["Add feature"],
    nonGoals: [],
    assumptions: [],
    invariants: ["Fail closed"],
    design: "Use the existing pipeline.",
    phases: [{
      title: "Implementation",
      changes: ["Add behavior"],
      codeTouchpoints: ["crates/firma-sidecar/src/pipeline.rs"],
      tests: ["Add a unit test"],
      documentation: [],
      gate: ["just check"],
    }],
    risks: [],
    acceptanceCriteria: ["Feature works"],
    verificationCommands: ["just check"],
  },
};

const projectionState = PlanningStateSchema.parse({
  issueIdentifier: "FIR-123",
  attempt: 2,
  planningRunId: "11111111-1111-4111-8111-111111111111",
  startedAt: "2026-07-24T10:00:00.000Z",
  phase: "implementation_ready",
  repositoryRevision: "abc123",
  currentCandidateVersion: 2,
  completedReviewAttempts: 2,
  triggerEventId: "webhook-7",
  initialStatusId: "Backlog status must not be rendered",
  updatedAt: "2026-07-24T10:05:00.000Z",
});

const projectionReport: ReviewReport = {
  attempt: 2,
  candidateVersion: 1,
  verdict: "changes_required",
  summary: "The first candidate needs revision.",
  findings: [finding()],
  residualRisks: ["A residual risk"],
};

const projectionArtifacts: Artifact[] = [{
  attempt: 2,
  kind: "input_snapshot",
  filename: "planning-input.json",
  contentType: "application/json",
  digest: "1".repeat(64),
  status: "confirmed",
  url: "https://uploads.linear.app/input.json",
  createdAt: "2026-07-24T10:01:00.000Z",
  uploadedAt: "2026-07-24T10:01:00.000Z",
}, {
  attempt: 2,
  kind: "candidate",
  candidateVersion: 1,
  filename: "candidate-v1.md",
  contentType: "text/markdown",
  digest: "2".repeat(64),
  status: "confirmed",
  url: "https://uploads.linear.app/candidate-v1.md",
  createdAt: "2026-07-24T10:02:00.000Z",
  uploadedAt: "2026-07-24T10:02:00.000Z",
}, {
  attempt: 2,
  kind: "review",
  candidateVersion: 1,
  reviewAttempt: 1,
  filename: "review-1.md",
  contentType: "text/markdown",
  digest: "3".repeat(64),
  status: "confirmed",
  url: "https://uploads.linear.app/review-1.md",
  createdAt: "2026-07-24T10:03:00.000Z",
  uploadedAt: "2026-07-24T10:03:00.000Z",
}, {
  attempt: 2,
  kind: "candidate",
  candidateVersion: 2,
  filename: "candidate-v2.md",
  contentType: "text/markdown",
  digest: "4".repeat(64),
  status: "confirmed",
  url: "https://uploads.linear.app/candidate-v2.md",
  createdAt: "2026-07-24T10:04:00.000Z",
  uploadedAt: "2026-07-24T10:04:00.000Z",
}];

const projectionReview: ReviewRecord = {
  attempt: 2,
  reviewAttempt: 1,
  report: projectionReport,
};

Deno.test("cumulative comment keeps final artifact visible and history collapsed", () => {
  const body = renderPlanningComment({
    state: projectionState,
    modelName: "openfirma-plan-fir-123",
    candidates: [{ version: 1 }, { version: 2 }],
    reviews: [projectionReview],
    artifacts: projectionArtifacts,
    outcome: {
      attempt: 2,
      kind: "implementation_ready",
      summary: "ready",
      candidateVersion: 2,
      planDigest: "4".repeat(64),
      artifactUrl: "https://uploads.linear.app/candidate-v2.md",
      updatedAt: projectionState.updatedAt,
    },
    materialization: null,
  });
  assertStringIncludes(
    body,
    "**Plan:** [candidate-v2.md](https://uploads.linear.app/candidate-v2.md)",
  );
  assert(body.startsWith("**Status:** Ready for review"));
  assertEquals(body.includes("## Ready for review"), false);
  assertStringIncludes(
    body,
    "swamp model method run openfirma-plan-fir-123 approvePlan",
  );
  assertStringIncludes(
    body,
    "swamp workflow run @openfirma/feature-planning --input ticket_id=FIR-123",
  );
  assertEquals(body.includes("## Final plan"), false);
  assertEquals(body.includes("**Repository:**"), false);
  assertStringIncludes(body, "+++ Diagnostics and recovery");
  const runDetailsStart = body.indexOf("+++ Run details");
  assert(
    body.indexOf(
      "`openfirma-planning:run=11111111-1111-4111-8111-111111111111`",
    ) > runDetailsStart,
  );
  assertStringIncludes(
    body,
    "[`abc123`](https://github.com/openfirma/openfirma/commit/abc123)",
  );
  assertEquals(body.startsWith("openfirma-planning:run="), false);
  const historyStart = body.indexOf("+++ Planning history");
  assert(
    body.indexOf(
      "[candidate-v1.md](https://uploads.linear.app/candidate-v1.md)\nSHA-256:",
    ) > historyStart,
  );
  assert(
    body.indexOf(
      "[review-1.md](https://uploads.linear.app/review-1.md)\nSHA-256:",
    ) > historyStart,
  );
  assert(body.indexOf("ADV-1 (high, correctness)") > historyStart);
  assert(body.indexOf("candidate-v2.md") < historyStart);
  assertEquals(body.includes(baseline.title), false);
  assertEquals(body.includes("project-id"), false);
  assertEquals(body.includes("Backlog status must not be rendered"), false);
});

Deno.test("needs-input comment uses the shared concise artifact template", () => {
  const body = renderPlanningComment({
    state: { ...projectionState, phase: "needs_input" },
    modelName: "openfirma-plan-fir-123",
    candidates: [],
    reviews: [],
    artifacts: [{
      attempt: 2,
      kind: "required_input",
      filename: "required-input-attempt-2.md",
      contentType: "text/markdown",
      digest: "5".repeat(64),
      status: "confirmed",
      url: "https://uploads.linear.app/required-input.md",
      createdAt: "2026-07-24T10:05:00.000Z",
    }],
    outcome: {
      attempt: 2,
      kind: "needs_input",
      summary: "Long blocker analysis that belongs in the artifact",
      blockingQuestions: [{
        question: "Which path should change?",
        whyBlocking: "No target is specified.",
      }],
      updatedAt: projectionState.updatedAt,
    },
    materialization: null,
  });
  assert(body.startsWith("**Status:** Needs input"));
  assertStringIncludes(
    body,
    "**Required input:** [required-input-attempt-2.md](https://uploads.linear.app/required-input.md)",
  );
  assertStringIncludes(
    body,
    "swamp workflow run @openfirma/feature-planning --input ticket_id=FIR-123",
  );
  assertEquals(body.includes("Long blocker analysis"), false);
  assertEquals(body.includes("Which path should change?"), false);
  assertEquals(body.startsWith("#"), false);
});

Deno.test("cumulative comment redacts ticket-visible values from agent text", () => {
  const body = renderPlanningComment({
    state: projectionState,
    modelName: "openfirma-plan-fir-123",
    candidates: [{ version: 1 }],
    reviews: [{
      ...projectionReview,
      report: {
        ...projectionReview.report,
        summary:
          "FIR-123 Plan feature belongs to Automation Experiments and needs revision.",
        findings: [{
          ...finding(),
          problem: "Plan feature repeats FIR-123",
        }],
      },
    }],
    artifacts: projectionArtifacts,
    outcome: {
      attempt: 2,
      kind: "review_exhausted",
      summary: "Automation Experiments cannot approve Plan feature",
      candidateVersion: 1,
      updatedAt: projectionState.updatedAt,
    },
    materialization: null,
    ticketVisibleValues: [
      "FIR-123",
      "Plan feature",
      "Automation Experiments",
    ],
  });
  assertEquals(body.includes("FIR-123"), false);
  assertEquals(body.includes("Plan feature"), false);
  assertEquals(body.includes("Automation Experiments"), false);
  assertStringIncludes(body, "\\[ticket field\\]");
});

Deno.test("cumulative comment escapes agent-controlled Markdown", () => {
  const body = renderPlanningComment({
    state: projectionState,
    modelName: "openfirma-plan-fir-123",
    candidates: [{ version: 1 }],
    reviews: [
      {
        ...projectionReview,
        report: {
          ...projectionReview.report,
          summary:
            "---\nSummary\n+++\n## Forged section\n[external](https://example.com)",
          findings: [{
            ...finding(),
            problem: "Problem\n- forged list item",
          }],
        },
      },
      {
        ...projectionReview,
        reviewAttempt: 2,
        report: { ...projectionReview.report, summary: "1. Forged list" },
      },
    ],
    artifacts: projectionArtifacts,
    outcome: null,
    materialization: null,
  });
  assertStringIncludes(
    body,
    "\\-\\-\\- Summary \\+\\+\\+ \\#\\# Forged section",
  );
  assertStringIncludes(body, "\\[external\\]\\(https: / /example.com\\)");
  assertStringIncludes(body, "Problem - forged list item");
  assertStringIncludes(body, "1\\. Forged list");
  assertEquals(body.includes("https://example.com"), false);
});

Deno.test("run marker is stable and incomplete state is rejected", () => {
  assertEquals(
    planningRunMarker(projectionState.planningRunId),
    "openfirma-planning:run=11111111-1111-4111-8111-111111111111",
  );
  assertEquals(PlanningStateSchema.safeParse({
    issueIdentifier: "FIR-450",
    attempt: 1,
    phase: "planning",
    completedReviewAttempts: 0,
    updatedAt: "2026-07-23T12:00:00.000Z",
  }).success, false);
  assert(PlanningStateSchema.safeParse({
    ...projectionState,
    phase: "implementation_approved",
  }).success);
});

Deno.test("current schemas reject removed development shapes", () => {
  assert(GlobalArgsSchema.safeParse(globalArgs).success);
  assertEquals(GlobalArgsSchema.safeParse({
    ...globalArgs,
    statusIds: {
      planning: "state-id",
      needsInput: "state-id",
      planningFailed: "state-id",
      awaitingApproval: "state-id",
      readyForImplementation: "state-id",
      planned: "in-progress",
    },
    allowedIntakeStatusIds: ["state-id"],
  }).success, false);
  assertEquals(TicketBaselineSchema.safeParse({
    ...baseline,
    projectName: undefined,
  }).success, false);
  assertEquals(ArtifactSchema.safeParse({
    ...projectionArtifacts[0],
    uploadedAt: undefined,
  }).success, false);
  assertEquals(MaterializationSchema.safeParse({
    attempt: 1,
    candidateVersion: 1,
    planDigest: "a".repeat(64),
    workflowRunId: "11111111-1111-4111-8111-111111111111",
    issueIdentifier: "FIR-123",
    artifactUrl: "https://uploads.linear.app/plan.md",
    childCount: 1,
    ticketUpdatedAt: baseline.updatedAt,
    ticketChangedSincePlanning: false,
    childIds: { api: "child-id" },
    childIdentifiers: {},
    relationKeys: [],
    preparedAt: baseline.updatedAt,
  }).success, false);
});

Deno.test("versioned records enumerate history from latest metadata", async () => {
  const encoded = new Map([
    [1, new TextEncoder().encode(JSON.stringify({
      ...candidate,
      authorRound: 1,
    }))],
    [2, new TextEncoder().encode(JSON.stringify({
      ...candidate,
      authorRound: 2,
    }))],
  ]);
  const context = {
    modelType: "@openfirma/feature-planning",
    modelId: "model-id",
    dataRepository: {
      findAllForModel: () => Promise.resolve([{
        name: "candidate-main",
        version: 2,
      }]),
      getContent: (
        _modelType: string,
        _modelId: string,
        _name: string,
        version: number,
      ) => Promise.resolve(encoded.get(version) ?? null),
    },
  };
  const history = await records(context as never, "candidate-main", CandidateSchema);
  assertEquals(history.map((record) => record.version), [1, 2]);
  assertEquals(history.map((record) => record.value.authorRound), [1, 2]);
});

Deno.test("cumulative comment includes materialization approval and progress", () => {
  const body = renderPlanningComment({
    state: { ...projectionState, phase: "children_created" },
    modelName: "openfirma-plan-fir-123",
    candidates: [{ version: 2 }],
    reviews: [],
    artifacts: projectionArtifacts,
    outcome: {
      attempt: 2,
      kind: "children_created",
      summary: "complete",
      candidateVersion: 2,
      planDigest: "4".repeat(64),
      childIds: { api: "child-1" },
      materializationRunId: "22222222-2222-4222-8222-222222222222",
      updatedAt: projectionState.updatedAt,
    },
    materialization: {
      attempt: 2,
      candidateVersion: 2,
      planDigest: "4".repeat(64),
      workflowRunId: "22222222-2222-4222-8222-222222222222",
      issueIdentifier: "FIR-123",
      artifactUrl: "https://uploads.linear.app/candidate-v2.md",
      childCount: 1,
      ticketUpdatedAt: projectionState.updatedAt,
      ticketChangedSincePlanning: true,
      childIds: { api: "child-1" },
      childIdentifiers: { api: "FIR-451" },
      relationKeys: ["api->client"],
      preparedAt: projectionState.updatedAt,
    },
  });
  assertStringIncludes(
    body,
    "Approval ID: `22222222-2222-4222-8222-222222222222`",
  );
  assertStringIncludes(body, "Ticket drift detected: true");
  assertStringIncludes(body, "api=`FIR-451`");
  assertStringIncludes(body, "api->client");
});

Deno.test("canonical digest ignores object key insertion order", async () => {
  assertEquals(
    canonicalJson({ b: 2, a: { d: 4, c: 3 } }),
    '{"a":{"c":3,"d":4},"b":2}',
  );
  assertEquals(await sha256({ b: 2, a: 1 }), await sha256({ a: 1, b: 2 }));
});

Deno.test("decomposition rejects duplicate keys", () => {
  const result = DecompositionSchema.safeParse({
    attempt: 1,
    ticket: "FIR-123",
    repositoryRevision: "abc123",
    objective: "Split work",
    whyDecompositionIsRequired: ["Independent deliverables"],
    sharedConstraints: [],
    childTickets: [
      child("api", 1, ["api"]),
      child("api", 2, []),
    ],
    integrationStrategy: ["Merge in order"],
    overallAcceptanceCriteria: ["Integrated"],
  });
  assertEquals(result.success, false);
  if (!result.success) {
    const messages = result.error.issues.map((issue) => issue.message).join("\n");
    assertStringIncludes(messages, "Duplicate child key");
  }
});

Deno.test("decomposition rejects dependency cycles", () => {
  const result = DecompositionSchema.safeParse({
    attempt: 1,
    ticket: "FIR-123",
    repositoryRevision: "abc123",
    objective: "Split work",
    whyDecompositionIsRequired: ["Independent deliverables"],
    sharedConstraints: [],
    childTickets: [child("api", 1, ["client"]), child("client", 2, ["api"])],
    integrationStrategy: ["Merge in order"],
    overallAcceptanceCriteria: ["Integrated"],
  });
  assertEquals(result.success, false);
  if (!result.success) {
    const messages = result.error.issues.map((issue) => issue.message).join("\n");
    assertStringIncludes(messages, "must form a DAG");
  }
});

Deno.test("review contract rejects contradictory verdicts", () => {
  assertEquals(ReviewReportSchema.safeParse({
    attempt: 1,
    candidateVersion: 2,
    verdict: "approved",
    summary: "Approved",
    findings: [finding()],
    residualRisks: [],
  }).success, false);
  assertEquals(ReviewReportSchema.safeParse({
    attempt: 1,
    candidateVersion: 2,
    verdict: "changes_required",
    summary: "Changes needed",
    findings: [],
    residualRisks: [],
  }).success, false);
});

Deno.test("review artifact includes every structured finding field", () => {
  const rendered = renderReview(projectionReview.report);
  assertStringIncludes(rendered, "Verdict: **changes_required**");
  assertStringIncludes(rendered, "The first candidate needs revision.");
  assertStringIncludes(rendered, "Category: correctness");
  assertStringIncludes(rendered, "Location: phase 1");
  assertStringIncludes(rendered, "Problem: Missing test");
  assertStringIncludes(rendered, "Required change: Add test");
  assertStringIncludes(rendered, "A residual risk");
});

Deno.test("fresh reviewer prompt excludes repair-only context", () => {
  const reviewer = buildReviewerPrompt(baseline, candidate, 7);
  assertStringIncludes(reviewer, "candidateVersion 7");
  assertEquals(reviewer.includes("SECRET_REPAIR_RATIONALE"), false);

  const author = buildAuthorPrompt(baseline, "abc123", 1, {
    candidate,
    review: {
      attempt: 1,
      candidateVersion: 7,
      verdict: "changes_required",
      summary: "SECRET_REPAIR_RATIONALE",
      findings: [finding()],
      residualRisks: [],
    },
  });
  assertStringIncludes(author, "SECRET_REPAIR_RATIONALE");
});

Deno.test("decomposition rendering is stable and digest-bound", () => {
  const plan = DecompositionSchema.parse({
    attempt: 1,
    ticket: "FIR-123",
    repositoryRevision: "abc123",
    objective: "Split work",
    whyDecompositionIsRequired: ["Independent deliverables"],
    sharedConstraints: [],
    childTickets: [child("second", 2, ["first"]), child("first", 1, [])],
    integrationStrategy: ["First, then second"],
    overallAcceptanceCriteria: ["Integrated"],
  });
  const rendered = renderDecomposition(plan, "a".repeat(64));
  assert(rendered.indexOf("## 1. First") < rendered.indexOf("## 2. Second"));
  assertStringIncludes(rendered, `Plan digest: \`${"a".repeat(64)}\``);
});

Deno.test("child marker binds all reconciliation dimensions", () => {
  assertEquals(
    childMarker("openfirma-plan-fir-123", 2, "a".repeat(64), "api"),
    `openfirma-planning-child:model=openfirma-plan-fir-123;attempt=2;digest=${"a".repeat(64)};key=api`,
  );
});

Deno.test("ticket drift ignores lifecycle projection but includes human comments", async () => {
  const projected = {
    ...baseline,
    comments: [{
      id: "workflow-comment",
      body:
        "openfirma-planning:run=11111111-1111-4111-8111-111111111111\n\nPlanning",
      createdAt: baseline.capturedAt,
      updatedAt: baseline.capturedAt,
    }],
  };
  assertEquals(
    await sha256(planningTicketContent(baseline, "workflow-comment")),
    await sha256(planningTicketContent(projected, "workflow-comment")),
  );
  projected.comments.push({
    id: "human-comment",
    body: "Please include Windows support",
    createdAt: baseline.capturedAt,
    updatedAt: baseline.capturedAt,
  });
  assert(
    await sha256(planningTicketContent(baseline, "workflow-comment")) !==
      await sha256(planningTicketContent(projected, "workflow-comment")),
  );
  projected.comments.push({
    id: "spoofed-marker",
    body:
      "openfirma-planning:run=22222222-2222-4222-8222-222222222222\n\nSpoof",
    createdAt: baseline.capturedAt,
    updatedAt: baseline.capturedAt,
  });
  assert(
    (planningTicketContent(projected, "workflow-comment").comments as unknown[])
        .length === 2,
  );
});

Deno.test("Codex environment excludes service credentials", () => {
  const original = Deno.env.get("LINEAR_API_KEY");
  Deno.env.set("LINEAR_API_KEY", "must-not-leak");
  try {
    const environment = codexEnvironment();
    assertEquals(environment.LINEAR_API_KEY, undefined);
    assert(environment.HOME !== undefined);
    assert(environment.PATH !== undefined);
  } finally {
    if (original === undefined) Deno.env.delete("LINEAR_API_KEY");
    else Deno.env.set("LINEAR_API_KEY", original);
  }
});

Deno.test({
  name: "Codex tool sandbox denies reads outside the immutable checkout",
  ignore: Deno.build.os === "windows",
  fn: async () => {
    const root = await Deno.makeTempDir({ prefix: "codex-sandbox-test-" });
    const checkout = `${root}/checkout`;
    const sentinel = `${root}/outside-secret`;
    await Deno.mkdir(checkout);
    await Deno.writeTextFile(sentinel, "must-not-be-readable");
    try {
      const output = await new Deno.Command("codex", {
        args: [
          "sandbox",
          "--permissions-profile",
          "openfirma-planning",
          "-C",
          checkout,
          ...codexPermissionArguments().slice(4),
          "--",
          "/bin/cat",
          sentinel,
        ],
        stdout: "piped",
        stderr: "piped",
      }).output();
      assertEquals(output.success, false);
      assertEquals(new TextDecoder().decode(output.stdout), "");
    } finally {
      await Deno.remove(root, { recursive: true });
    }
  },
});

Deno.test("repository snapshot materializes the exact revision", async () => {
  const repoDir = new URL("../../../", import.meta.url).pathname.replace(/\/$/, "");
  const resolved = await resolveRepositoryRevision(repoDir);
  assertMatch(resolved.revision, /^[a-f0-9]{40,64}$/);
  const archived = await archiveRepository(repoDir, resolved.revision, resolved.vcs);
  try {
    const agents = await Deno.readTextFile(`${archived.checkout}/AGENTS.md`);
    assertStringIncludes(agents, "Swamp Automation");
    assertEquals(await exists(`${archived.checkout}/.jj`), false);
  } finally {
    await Deno.remove(archived.root, { recursive: true });
  }
});

Deno.test("Linear adapter classifies authentication failure", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = () =>
    Promise.resolve(new Response("Unauthorized", { status: 401 }));
  try {
    const client = new LinearClient("https://api.linear.app/graphql", "bad-key");
    await assertRejects(
      () => client.fetchIssue("FIR-123", 1),
      Error,
      "authentication failed",
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

Deno.test("Linear adapter does not replay an ambiguous comment creation", async () => {
  let requests = 0;
  const marker = "<!-- planning-run:test -->";
  const originalFetch = globalThis.fetch;
  globalThis.fetch = () => {
    requests += 1;
    return Promise.resolve(new Response("Unavailable", { status: 503 }));
  };
  try {
    const client = new LinearClient("https://api.linear.app/graphql", "test-key");
    await assertRejects(
      () =>
        client.upsertLifecycleComment(
          baseline,
          marker,
          `Planning in progress\n\n${marker}`,
        ),
      Error,
      "HTTP 503",
    );
    assertEquals(requests, 1);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

Deno.test("Linear adapter adopts a lifecycle marker nested in run details", async () => {
  let mutation = "";
  const marker = "openfirma-planning:run=11111111-1111-4111-8111-111111111111";
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (_input, init) => {
    const request = JSON.parse(String(init?.body)) as { query: string };
    mutation = request.query;
    return Promise.resolve(new Response(JSON.stringify({
      data: {
        commentUpdate: { success: true, comment: { id: "comment-id" } },
      },
    }), { status: 200 }));
  };
  try {
    const client = new LinearClient("https://api.linear.app/graphql", "test-key");
    const commentId = await client.upsertLifecycleComment(
      {
        ...baseline,
        comments: [{
          id: "comment-id",
          body: `## Ready for review\n\n+++ Run details\n- Planning run: \`${marker}\`\n+++`,
          createdAt: baseline.capturedAt,
          updatedAt: baseline.updatedAt,
        }],
      },
      marker,
      `## Plan approved\n\n+++ Run details\n- Planning run: \`${marker}\`\n+++`,
    );
    assertEquals(commentId, "comment-id");
    assertStringIncludes(mutation, "UpdatePlanningComment");
    assertEquals(mutation.includes("CreatePlanningComment"), false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

Deno.test("Linear adapter does not replay child or relation creation", async () => {
  const originalFetch = globalThis.fetch;
  try {
    for (
      const operation of [
        (client: LinearClient) =>
          client.createChild({
            teamId: "team-id",
            projectId: "project-id",
            parentId: "parent-id",
            title: "Child",
            description: "marker",
          }),
        (client: LinearClient) =>
          client.createBlockingRelation("blocker-id", "blocked-id"),
      ]
    ) {
      let requests = 0;
      globalThis.fetch = () => {
        requests += 1;
        return Promise.resolve(new Response("Unavailable", { status: 503 }));
      };
      const client = new LinearClient(
        "https://api.linear.app/graphql",
        "test-key",
      );
      await assertRejects(() => operation(client), Error, "HTTP 503");
      assertEquals(requests, 1);
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
});

Deno.test("getOutcome does not create new data versions", async () => {
  let writes = 0;
  const state = {
    issueIdentifier: "FIR-123",
    attempt: 1,
    planningRunId: "11111111-1111-4111-8111-111111111111",
    startedAt: "2026-07-23T12:00:00.000Z",
    phase: "needs_input",
    completedReviewAttempts: 0,
    initialStatusId: "state-id",
    updatedAt: "2026-07-23T12:00:00.000Z",
  };
  const context = {
    readResource: (name: string) =>
      Promise.resolve(name === "state-main" ? state : null),
    writeResource: () => {
      writes += 1;
      return Promise.resolve({});
    },
    logger: { info: () => {}, warning: () => {}, error: () => {} },
  };
  const result = await model.methods.getOutcome.execute({}, context as never);
  assertEquals(result.dataHandles, []);
  assertEquals(writes, 0);
});

Deno.test("model instance cannot be rebound to a different ticket", async () => {
  const context = {
    definition: { name: "openfirma-plan-fir-123" },
    readResource: (name: string) => Promise.resolve(name === "state-main" ? {
      issueIdentifier: "FIR-123",
      attempt: 1,
      planningRunId: "11111111-1111-4111-8111-111111111111",
      startedAt: "2026-07-23T12:00:00.000Z",
      phase: "needs_input",
      completedReviewAttempts: 0,
      initialStatusId: "state-id",
      updatedAt: "2026-07-23T12:00:00.000Z",
    } : null),
  };
  await assertRejects(
    () =>
      model.methods.plan.execute(
        { ticketId: "FIR-456" },
        context as never,
      ),
    Error,
    "belongs to FIR-123",
  );
});

Deno.test("status projection confirms each phase and preserves human changes", async () => {
  const originalFetch = globalThis.fetch;
  const resources = new Map<string, unknown>();
  const effectNames: string[] = [];
  let currentStatusId = "state-id";
  let issueFetches = 0;
  let statusUpdates = 0;
  globalThis.fetch = (_input, init) => {
    const request = JSON.parse(String(init?.body)) as { query: string };
    if (request.query.includes("PlanningIssue")) {
      issueFetches += 1;
      return Promise.resolve(new Response(JSON.stringify({
        data: {
          issue: {
            ...baseline,
            project: { id: baseline.projectId, name: baseline.projectName },
            team: { id: baseline.teamId },
            state: { id: currentStatusId, name: "Current" },
            comments: {
              nodes: [],
              pageInfo: { hasNextPage: false, endCursor: null },
            },
          },
        },
      }), { status: 200 }));
    }
    if (request.query.includes("UpdateIssueStatus")) {
      statusUpdates += 1;
      return Promise.resolve(new Response(JSON.stringify({
        data: { issueUpdate: { success: true } },
      }), { status: 200 }));
    }
    throw new Error("Unexpected Linear operation");
  };
  const context = {
    globalArgs,
    logger: { info: () => {}, warning: () => {}, error: () => {} },
    readResource: (name: string) => Promise.resolve(resources.get(name) ?? null),
    writeResource: (
      specName: string,
      name: string,
      data: Record<string, unknown>,
    ) => {
      resources.set(name, data);
      if (specName === "effects") effectNames.push(name);
      return Promise.resolve({ specName, name, version: 1 });
    },
  };
  try {
    assert(await projectStatus(context as never, projectionState, "state-id"));
    assert(await projectStatus(
      context as never,
      { ...projectionState, phase: "needs_input" },
      "state-id",
    ));
    assertEquals(issueFetches, 2);
    assert(effectNames.includes("effect-status-implementation_ready-state-id"));
    assert(effectNames.includes("effect-status-needs_input-state-id"));

    currentStatusId = "human-selected-status";
    assertEquals(
      await projectStatus(
        context as never,
        { ...projectionState, phase: "failed" },
        "state-id",
        true,
      ),
      false,
    );
    assertEquals(statusUpdates, 0);
    await assertRejects(
      () =>
        projectPhase(
          context as never,
          { ...projectionState, phase: "failed" },
          "state-id",
          true,
        ),
      Error,
      "Linear phase projection is not fully confirmed",
    );
    assertEquals(
      (resources.get("effect-phase-failed") as { status: string }).status,
      "failed",
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

Deno.test("prepareMaterialization resumes only after comment confirmation", async () => {
  const workflowRunId = "11111111-1111-4111-8111-111111111111";
  const stored = {
    attempt: 1,
    candidateVersion: 3,
    planDigest: "a".repeat(64),
    workflowRunId,
    issueIdentifier: "FIR-123",
    artifactUrl: "https://uploads.linear.app/plan.md",
    childCount: 2,
    ticketUpdatedAt: "2026-07-23T12:00:00.000Z",
    ticketChangedSincePlanning: false,
    childIds: {},
    childIdentifiers: {},
    relationKeys: [],
    preparedAt: "2026-07-23T12:00:00.000Z",
  };
  const writes: Array<{ name: string; data: Record<string, unknown> }> = [];
  let lifecycleEffect: Record<string, unknown> | null = null;
  let rejectComment = false;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (_input, init) => {
    const request = JSON.parse(String(init?.body)) as { query: string };
    if (request.query.includes("PlanningIssue")) {
      return Promise.resolve(new Response(JSON.stringify({
        data: {
          issue: {
            ...baseline,
            project: { id: baseline.projectId },
            team: { id: baseline.teamId },
            state: { id: baseline.stateId, name: baseline.stateName },
            comments: {
              nodes: [],
              pageInfo: { hasNextPage: false, endCursor: null },
            },
          },
        },
      }), { status: 200 }));
    }
    if (rejectComment) {
      return Promise.resolve(new Response("Unavailable", { status: 503 }));
    }
    return Promise.resolve(new Response(JSON.stringify({
      data: {
        commentCreate: { success: true, comment: { id: "comment-id" } },
      },
    }), { status: 200 }));
  };
  const context = {
    modelType: "@openfirma/feature-planning",
    modelId: "model-id",
    definition: { name: "openfirma-plan-fir-123" },
    globalArgs,
    logger: { info: () => {}, warning: () => {}, error: () => {} },
    readResource: (name: string) => Promise.resolve(
      name === "state-main"
        ? {
          issueIdentifier: "FIR-123",
          attempt: 1,
          planningRunId: "11111111-1111-4111-8111-111111111111",
          startedAt: "2026-07-23T12:00:00.000Z",
          phase: "awaiting_approval",
          completedReviewAttempts: 1,
          activeMaterializationRunId: workflowRunId,
          initialStatusId: "state-id",
          updatedAt: "2026-07-23T12:00:00.000Z",
        }
         : name === `materialization-${workflowRunId}`
         ? stored
         : name === "effect-lifecycle-comment"
         ? lifecycleEffect
         : null,
    ),
    writeResource: (
      specName: string,
      name: string,
      data: Record<string, unknown>,
    ) => {
      writes.push({ name, data });
      if (name === "effect-lifecycle-comment") lifecycleEffect = data;
      return Promise.resolve({ name, specName, version: 2 });
    },
    dataRepository: {
      findAllForModel: () => Promise.resolve([{
        name: `materialization-${workflowRunId}`,
        version: 1,
      }]),
      getContent: (
        _type: string,
        _modelId: string,
        name: string,
      ) =>
        Promise.resolve(
          name === `materialization-${workflowRunId}`
            ? new TextEncoder().encode(JSON.stringify(stored))
            : null,
        ),
    },
  };
  try {
    const result = await model.methods.prepareMaterialization.execute(
      {
        candidateVersion: 3,
        planDigest: "a".repeat(64),
        workflowRunId,
      },
      context as never,
    );
    assertEquals(
      result.dataHandles[0]?.name,
      `materialization-${workflowRunId}`,
    );
    assertEquals(writes[0].data, stored);
    assert(writes.some((write) => write.name === "effect-lifecycle-comment"));

    rejectComment = true;
    await assertRejects(
      () =>
        model.methods.prepareMaterialization.execute(
          {
            candidateVersion: 3,
            planDigest: "a".repeat(64),
            workflowRunId,
          },
          context as never,
        ),
      Error,
      "cumulative Linear comment is not confirmed",
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

Deno.test("materialize rejects a stale approval ID", async () => {
  const active = "11111111-1111-4111-8111-111111111111";
  const stale = "22222222-2222-4222-8222-222222222222";
  const context = {
    readResource: (name: string) => Promise.resolve(name === "state-main" ? {
      issueIdentifier: "FIR-123",
      attempt: 1,
      planningRunId: "11111111-1111-4111-8111-111111111111",
      startedAt: "2026-07-23T12:00:00.000Z",
      phase: "awaiting_approval",
      completedReviewAttempts: 1,
      activeMaterializationRunId: active,
      initialStatusId: "state-id",
      updatedAt: "2026-07-23T12:00:00.000Z",
    } : null),
  };
  await assertRejects(
    () =>
      model.methods.materialize.execute(
        {
          candidateVersion: 3,
          planDigest: "a".repeat(64),
          workflowRunId: stale,
        },
        context as never,
      ),
    Error,
    "not bound to the active approval",
  );
});

function child(key: string, ordinal: number, dependencies: string[]) {
  const title = key[0].toUpperCase() + key.slice(1);
  return {
    key,
    ordinal,
    title,
    descriptionMarkdown: `${title} child`,
    acceptanceCriteria: ["Done"],
    dependencies,
  };
}

function finding() {
  return {
    id: "ADV-1",
    severity: "high" as const,
    category: "correctness",
    location: "phase 1",
    problem: "Missing test",
    requiredChange: "Add test",
  };
}

async function exists(path: string): Promise<boolean> {
  try {
    await Deno.stat(path);
    return true;
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) return false;
    throw error;
  }
}
