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
  planningTicketContent,
  renderDecomposition,
  sha256,
} from "./helpers.ts";
import { assertAllowedProject, model } from "./model.ts";
import {
  type Candidate,
  DecompositionSchema,
  type GlobalArgs,
  ReviewReportSchema,
  type TicketBaseline,
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
    planning: "planning",
    needsInput: "needs-input",
    planningFailed: "planning-failed",
    awaitingApproval: "awaiting-approval",
    readyForImplementation: "ready-for-implementation",
    planned: "planned",
  },
  allowedIntakeStatusIds: [],
  allowedIntakeStatusIdsCsv: "",
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
      body: "openfirma-planning:model=openfirma-plan-fir-123;attempt=1\n\nPlanning",
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
    body: "openfirma-planning:model=openfirma-plan-fir-123;attempt=1\n\nSpoof",
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

Deno.test("getOutcome does not create new data versions", async () => {
  let writes = 0;
  const state = {
    issueIdentifier: "FIR-123",
    attempt: 1,
    phase: "needs_input",
    completedReviewAttempts: 0,
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
      phase: "needs_input",
      completedReviewAttempts: 0,
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

Deno.test("prepareMaterialization resumes the same approval payload", async () => {
  const workflowRunId = "11111111-1111-4111-8111-111111111111";
  const stored = {
    attempt: 1,
    candidateVersion: 3,
    planDigest: "a".repeat(64),
    workflowRunId,
    issueIdentifier: "FIR-123",
    attachmentUrl: "https://uploads.linear.app/plan.md",
    childCount: 2,
    ticketUpdatedAt: "2026-07-23T12:00:00.000Z",
    ticketChangedSincePlanning: false,
    childIds: {},
    relationKeys: [],
    preparedAt: "2026-07-23T12:00:00.000Z",
  };
  const writes: Array<{ name: string; data: Record<string, unknown> }> = [];
  const context = {
    readResource: (name: string) => Promise.resolve(
      name === "state-main"
        ? {
          issueIdentifier: "FIR-123",
          attempt: 1,
          phase: "awaiting_approval",
          completedReviewAttempts: 1,
          activeMaterializationRunId: workflowRunId,
          updatedAt: "2026-07-23T12:00:00.000Z",
        }
        : name === `materialization-${workflowRunId}`
        ? stored
        : null,
    ),
    writeResource: (
      specName: string,
      name: string,
      data: Record<string, unknown>,
    ) => {
      writes.push({ name, data });
      return Promise.resolve({ name, specName, version: 2 });
    },
  };
  const result = await model.methods.prepareMaterialization.execute(
    {
      candidateVersion: 3,
      planDigest: "a".repeat(64),
      workflowRunId,
    },
    context as never,
  );
  assertEquals(result.dataHandles[0]?.name, `materialization-${workflowRunId}`);
  assertEquals(writes.length, 1);
  assertEquals(writes[0].data, stored);
});

Deno.test("materialize rejects a stale approval ID", async () => {
  const active = "11111111-1111-4111-8111-111111111111";
  const stale = "22222222-2222-4222-8222-222222222222";
  const context = {
    readResource: (name: string) => Promise.resolve(name === "state-main" ? {
      issueIdentifier: "FIR-123",
      attempt: 1,
      phase: "awaiting_approval",
      completedReviewAttempts: 1,
      activeMaterializationRunId: active,
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
