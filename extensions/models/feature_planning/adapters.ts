import { z } from "npm:zod@4.3.6";
import {
  AuthorResultSchema,
  type GlobalArgs,
  ReviewReportSchema,
  type TicketBaseline,
} from "./schemas.ts";

export class AdapterError extends Error {
  constructor(
    readonly kind:
      | "not_found"
      | "authentication"
      | "authorization"
      | "rate_limit"
      | "timeout"
      | "temporary"
      | "invalid_output"
      | "conflict",
    message: string,
    readonly retryable: boolean,
  ) {
    super(message);
    this.name = "AdapterError";
  }
}

type GraphqlResponse<T> = {
  data?: T;
  errors?: Array<{
    message: string;
    extensions?: { code?: string; type?: string };
  }>;
};

type LinearIssue = {
  id: string;
  identifier: string;
  title: string;
  description: string | null;
  url: string;
  updatedAt: string;
  team: { id: string };
  project: { id: string; name: string } | null;
  state: { id: string; name: string };
  comments: {
    nodes: Array<{
      id: string;
      body: string;
      createdAt: string;
      updatedAt: string;
    }>;
    pageInfo: { hasNextPage: boolean; endCursor: string | null };
  };
};

const ISSUE_QUERY = `
  query PlanningIssue($id: String!) {
    issue(id: $id) {
      id identifier title description url updatedAt
      team { id }
      project { id name }
      state { id name }
      comments(first: 100) {
        nodes { id body createdAt updatedAt }
        pageInfo { hasNextPage endCursor }
      }
    }
  }
`;

export class LinearClient {
  constructor(
    private readonly apiUrl: string,
    private readonly apiKey: string,
  ) {}

  private async request<T>(
    query: string,
    variables: Record<string, unknown>,
    options: { attempts?: number } = {},
  ): Promise<T> {
    let lastError: AdapterError | undefined;
    const attempts = options.attempts ?? 3;
    for (let requestAttempt = 0; requestAttempt < attempts; requestAttempt++) {
      try {
        const response = await fetch(this.apiUrl, {
          method: "POST",
          headers: {
            "Authorization": this.apiKey,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ query, variables }),
          signal: AbortSignal.timeout(30_000),
        });
        if (response.status === 401) {
          throw new AdapterError(
            "authentication",
            "Linear authentication failed",
            false,
          );
        }
        if (response.status === 403) {
          throw new AdapterError(
            "authorization",
            "Linear authorization failed",
            false,
          );
        }
        if (response.status === 429) {
          throw new AdapterError(
            "rate_limit",
            "Linear rate limit exceeded",
            true,
          );
        }
        if (response.status >= 500) {
          throw new AdapterError(
            "temporary",
            `Linear returned HTTP ${response.status}`,
            true,
          );
        }
        if (!response.ok) {
          throw new AdapterError(
            "conflict",
            `Linear returned HTTP ${response.status}`,
            false,
          );
        }

        const payload = await response.json() as GraphqlResponse<T>;
        if (payload.errors?.length) {
          const message = payload.errors.map((error) => error.message).join(
            "; ",
          );
          const type = payload.errors[0]?.extensions?.type?.toLowerCase();
          if (type === "ratelimited") {
            throw new AdapterError("rate_limit", message, true);
          }
          if (type === "authenticationerror") {
            throw new AdapterError("authentication", message, false);
          }
          if (type === "forbidden") {
            throw new AdapterError("authorization", message, false);
          }
          throw new AdapterError(
            "conflict",
            `Linear GraphQL error: ${message}`,
            false,
          );
        }
        if (!payload.data) {
          throw new AdapterError("temporary", "Linear returned no data", true);
        }
        return payload.data;
      } catch (error) {
        lastError = error instanceof AdapterError ? error : new AdapterError(
          error instanceof DOMException && error.name === "TimeoutError"
            ? "timeout"
            : "temporary",
          `Linear request failed: ${String(error)}`,
          true,
        );
        if (!lastError.retryable || requestAttempt === attempts - 1) {
          throw lastError;
        }
        await new Promise((resolve) =>
          setTimeout(resolve, 250 * (2 ** requestAttempt))
        );
      }
    }
    throw lastError ??
      new AdapterError("temporary", "Linear request failed", true);
  }

  async fetchIssue(
    identifier: string,
    attempt: number,
  ): Promise<TicketBaseline> {
    const data = await this.request<{ issue: LinearIssue | null }>(
      ISSUE_QUERY,
      {
        id: identifier,
      },
    );
    if (!data.issue) {
      throw new AdapterError(
        "not_found",
        `Linear issue ${identifier} was not found`,
        false,
      );
    }
    const comments = [...data.issue.comments.nodes];
    let pageInfo = data.issue.comments.pageInfo;
    while (pageInfo.hasNextPage) {
      if (!pageInfo.endCursor) {
        throw new AdapterError(
          "conflict",
          `Linear issue ${identifier} returned an invalid comments cursor`,
          false,
        );
      }
      const page = await this.request<{
        issue: null | { comments: LinearIssue["comments"] };
      }>(
        `query PlanningComments($id: String!, $after: String!) {
          issue(id: $id) {
            comments(first: 100, after: $after) {
              nodes { id body createdAt updatedAt }
              pageInfo { hasNextPage endCursor }
            }
          }
        }`,
        { id: identifier, after: pageInfo.endCursor },
      );
      if (!page.issue) {
        throw new AdapterError(
          "not_found",
          `Linear issue ${identifier} disappeared during pagination`,
          false,
        );
      }
      comments.push(...page.issue.comments.nodes);
      pageInfo = page.issue.comments.pageInfo;
    }
    return {
      attempt,
      id: data.issue.id,
      identifier: data.issue.identifier,
      title: data.issue.title,
      description: data.issue.description ?? "",
      url: data.issue.url,
      updatedAt: data.issue.updatedAt,
      teamId: data.issue.team.id,
      projectId: data.issue.project?.id ?? null,
      projectName: data.issue.project?.name ?? null,
      stateId: data.issue.state.id,
      stateName: data.issue.state.name,
      comments,
      capturedAt: new Date().toISOString(),
    };
  }

  async updateStatus(issueId: string, stateId: string): Promise<void> {
    const data = await this.request<{
      issueUpdate: { success: boolean };
    }>(
      `mutation UpdatePlanningStatus($id: String!, $stateId: String!) {
        issueUpdate(id: $id, input: { stateId: $stateId }) { success }
      }`,
      { id: issueId, stateId },
    );
    if (!data.issueUpdate.success) {
      throw new AdapterError(
        "conflict",
        "Linear status update was not confirmed",
        false,
      );
    }
  }

  async upsertLifecycleComment(
    baseline: TicketBaseline,
    marker: string,
    body: string,
  ): Promise<string> {
    if (!body.includes(marker)) {
      throw new AdapterError(
        "conflict",
        "Linear lifecycle comment body is missing its run marker",
        false,
      );
    }
    const matches = baseline.comments.filter((comment) =>
      comment.body.includes(marker)
    );
    if (matches.length > 1) {
      throw new AdapterError(
        "conflict",
        `Multiple Linear lifecycle comments match ${marker}`,
        false,
      );
    }
    const fullBody = body;
    if (matches[0]) {
      const data = await this.request<{
        commentUpdate: { success: boolean; comment: { id: string } | null };
      }>(
        `mutation UpdatePlanningComment($id: String!, $body: String!) {
          commentUpdate(id: $id, input: { body: $body }) { success comment { id } }
        }`,
        { id: matches[0].id, body: fullBody },
      );
      if (!data.commentUpdate.success || !data.commentUpdate.comment) {
        throw new AdapterError(
          "conflict",
          "Linear comment update was not confirmed",
          false,
        );
      }
      return data.commentUpdate.comment.id;
    }

    const data = await this.request<{
      commentCreate: { success: boolean; comment: { id: string } | null };
    }>(
      `mutation CreatePlanningComment($issueId: String!, $body: String!) {
        commentCreate(input: { issueId: $issueId, body: $body }) {
          success comment { id }
        }
      }`,
      { issueId: baseline.id, body: fullBody },
      // Reconcile an ambiguous create on the next projection instead of
      // replaying a mutation that may already have committed.
      { attempts: 1 },
    );
    if (!data.commentCreate.success || !data.commentCreate.comment) {
      throw new AdapterError(
        "conflict",
        "Linear comment creation was not confirmed",
        false,
      );
    }
    return data.commentCreate.comment.id;
  }

  async uploadAsset(
    filename: string,
    content: string,
    contentType: "application/json" | "text/markdown",
  ): Promise<string> {
    const bytes = new TextEncoder().encode(content);
    const upload = await this.request<{
      fileUpload: {
        success: boolean;
        uploadFile: {
          uploadUrl: string;
          assetUrl: string;
          headers: Array<{ key: string; value: string }>;
        } | null;
      };
    }>(
      `mutation PlanningFileUpload($contentType: String!, $filename: String!, $size: Int!) {
        fileUpload(contentType: $contentType, filename: $filename, size: $size) {
          success uploadFile { uploadUrl assetUrl headers { key value } }
        }
      }`,
      { contentType, filename, size: bytes.byteLength },
    );
    if (!upload.fileUpload.success || !upload.fileUpload.uploadFile) {
      throw new AdapterError(
        "temporary",
        "Linear file upload was not allocated",
        true,
      );
    }

    const headers = new Headers({ "Content-Type": contentType });
    for (const header of upload.fileUpload.uploadFile.headers) {
      headers.set(header.key, header.value);
    }
    let put: Response;
    try {
      put = await fetch(upload.fileUpload.uploadFile.uploadUrl, {
        method: "PUT",
        headers,
        body: bytes,
        signal: AbortSignal.timeout(30_000),
      });
    } catch (error) {
      throw new AdapterError(
        error instanceof DOMException && error.name === "TimeoutError"
          ? "timeout"
          : "temporary",
        `Linear file upload failed: ${String(error)}`,
        true,
      );
    }
    if (!put.ok) {
      throw new AdapterError(
        "temporary",
        `Linear file upload returned HTTP ${put.status}`,
        true,
      );
    }

    return upload.fileUpload.uploadFile.assetUrl;
  }

  async listChildren(parentId: string): Promise<
    Array<{
      id: string;
      identifier: string;
      title: string;
      description: string;
      projectId: string | null;
    }>
  > {
    const data = await this.request<{
      issue: null | {
        children: {
          nodes: Array<{
            id: string;
            identifier: string;
            title: string;
            description: string | null;
            project: { id: string } | null;
          }>;
          pageInfo: { hasNextPage: boolean };
        };
      };
    }>(
      `query PlanningChildren($id: String!) {
        issue(id: $id) {
          children(first: 100) {
            nodes { id identifier title description project { id } }
            pageInfo { hasNextPage }
          }
        }
      }`,
      { id: parentId },
    );
    if (!data.issue) {
      throw new AdapterError("not_found", "Parent issue was not found", false);
    }
    if (data.issue.children.pageInfo.hasNextPage) {
      throw new AdapterError(
        "conflict",
        "Parent has more than 100 children; reconciliation is ambiguous",
        false,
      );
    }
    return data.issue.children.nodes.map((child) => ({
      ...child,
      description: child.description ?? "",
      projectId: child.project?.id ?? null,
    }));
  }

  async createChild(input: {
    teamId: string;
    projectId: string;
    parentId: string;
    title: string;
    description: string;
  }): Promise<{ id: string; identifier: string }> {
    const data = await this.request<{
      issueCreate: {
        success: boolean;
        issue: { id: string; identifier: string } | null;
      };
    }>(
      `mutation CreatePlanningChild(
        $teamId: String!, $projectId: String!, $parentId: String!, $title: String!, $description: String!
      ) {
        issueCreate(input: {
          teamId: $teamId, projectId: $projectId, parentId: $parentId,
          title: $title, description: $description
        }) { success issue { id identifier } }
      }`,
      input,
      // Reconcile an ambiguous create by child marker on the next invocation.
      { attempts: 1 },
    );
    if (!data.issueCreate.success || !data.issueCreate.issue) {
      throw new AdapterError(
        "conflict",
        "Linear child creation was not confirmed",
        false,
      );
    }
    return data.issueCreate.issue;
  }

  async listRelations(issueId: string): Promise<
    Array<{
      id: string;
      type: string;
      issueId: string;
      relatedIssueId: string;
    }>
  > {
    type Relation = {
      id: string;
      type: string;
      issue: { id: string };
      relatedIssue: { id: string };
    };
    type ConnectionResponse = {
      issue: null | {
        connection: {
          nodes: Relation[];
          pageInfo: { hasNextPage: boolean; endCursor: string | null };
        };
      };
    };
    const fetchConnection = async (
      field: "relations" | "inverseRelations",
    ): Promise<Relation[]> => {
      const relations: Relation[] = [];
      let cursor: string | null = null;
      do {
        const data: ConnectionResponse = await this.request<ConnectionResponse>(
          `query PlanningRelations($id: String!, $after: String) {
            issue(id: $id) {
              connection: ${field}(first: 100, after: $after) {
                nodes { id type issue { id } relatedIssue { id } }
                pageInfo { hasNextPage endCursor }
              }
            }
          }`,
          { id: issueId, after: cursor },
        );
        if (!data.issue) {
          throw new AdapterError(
            "not_found",
            "Child issue was not found",
            false,
          );
        }
        relations.push(...data.issue.connection.nodes);
        cursor = data.issue.connection.pageInfo.hasNextPage
          ? data.issue.connection.pageInfo.endCursor
          : null;
        if (data.issue.connection.pageInfo.hasNextPage && !cursor) {
          throw new AdapterError(
            "conflict",
            "Linear returned an invalid relation cursor",
            false,
          );
        }
      } while (cursor);
      return relations;
    };
    const relations = [
      ...await fetchConnection("relations"),
      ...await fetchConnection("inverseRelations"),
    ];
    return relations.map((relation) => ({
      id: relation.id,
      type: relation.type,
      issueId: relation.issue.id,
      relatedIssueId: relation.relatedIssue.id,
    }));
  }

  async createBlockingRelation(
    blockerId: string,
    blockedId: string,
  ): Promise<string> {
    const data = await this.request<{
      issueRelationCreate: {
        success: boolean;
        issueRelation: { id: string } | null;
      };
    }>(
      `mutation CreatePlanningRelation($issueId: String!, $relatedIssueId: String!) {
        issueRelationCreate(input: {
          issueId: $issueId, relatedIssueId: $relatedIssueId, type: blocks
        }) { success issueRelation { id } }
      }`,
      { issueId: blockerId, relatedIssueId: blockedId },
      // Reconcile an ambiguous create from the relation list on the next invocation.
      { attempts: 1 },
    );
    if (
      !data.issueRelationCreate.success ||
      !data.issueRelationCreate.issueRelation
    ) {
      throw new AdapterError(
        "conflict",
        "Linear relation creation was not confirmed",
        false,
      );
    }
    return data.issueRelationCreate.issueRelation.id;
  }
}

type CommandResult = { success: boolean; stdout: string; stderr: string };

async function command(
  executable: string,
  args: string[],
  cwd: string,
  stdin?: string,
  env?: Record<string, string>,
  timeoutMs = 120_000,
): Promise<CommandResult> {
  const process = new Deno.Command(executable, {
    args,
    cwd,
    stdin: stdin === undefined ? "null" : "piped",
    stdout: "piped",
    stderr: "piped",
    clearEnv: env !== undefined,
    env,
  }).spawn();
  let timeout: ReturnType<typeof setTimeout> | undefined;
  try {
    const output = await Promise.race([
      (async () => {
        if (stdin !== undefined) {
          const writer = process.stdin.getWriter();
          await writer.write(new TextEncoder().encode(stdin));
          await writer.close();
        }
        return await process.output();
      })(),
      new Promise<never>((_resolve, reject) => {
        timeout = setTimeout(async () => {
          try {
            process.kill("SIGTERM");
          } catch {
            // The process may have exited between the timeout and termination.
          }
          const exited = await Promise.race([
            process.status.then(() => true),
            new Promise<boolean>((resolve) =>
              setTimeout(() => resolve(false), 2_000)
            ),
          ]);
          if (!exited) {
            try {
              process.kill("SIGKILL");
              await process.status;
            } catch {
              // The process may have exited before escalation completed.
            }
          }
          reject(
            new AdapterError(
              "timeout",
              `${executable} exceeded its ${
                Math.ceil(timeoutMs / 1000)
              }s timeout`,
              true,
            ),
          );
        }, timeoutMs);
      }),
    ]);
    return {
      success: output.success,
      stdout: new TextDecoder().decode(output.stdout),
      stderr: new TextDecoder().decode(output.stderr),
    };
  } finally {
    if (timeout !== undefined) clearTimeout(timeout);
  }
}

export async function resolveRepositoryRevision(
  repoDir: string,
  requested?: string,
): Promise<{ revision: string; vcs: "jj" | "git" }> {
  const target = requested ?? "@";
  const jj = await command(
    "jj",
    ["log", "--no-graph", "-r", target, "-T", 'commit_id ++ "\\n"'],
    repoDir,
  );
  if (jj.success && jj.stdout.trim()) {
    return { revision: jj.stdout.trim(), vcs: "jj" };
  }

  const gitTarget = requested ? `${requested}^{commit}` : "HEAD^{commit}";
  const git = await command(
    "git",
    ["rev-parse", "--verify", gitTarget],
    repoDir,
  );
  if (git.success && git.stdout.trim()) {
    return { revision: git.stdout.trim(), vcs: "git" };
  }
  throw new AdapterError(
    "conflict",
    `Could not resolve immutable repository revision ${requested ?? "current"}`,
    false,
  );
}

export async function archiveRepository(
  repoDir: string,
  revision: string,
  vcs: "jj" | "git",
): Promise<{ root: string; checkout: string }> {
  const root = await Deno.makeTempDir({ prefix: "openfirma-planning-" });
  const checkout = `${root}/repository`;
  await Deno.mkdir(checkout);
  const archive = `${root}/repository.tar`;
  const gitArgs = ["archive", "--format=tar", `--output=${archive}`, revision];
  if (vcs === "jj") {
    const gitRoot = await command("jj", ["git", "root"], repoDir);
    if (!gitRoot.success || !gitRoot.stdout.trim()) {
      await Deno.remove(root, { recursive: true });
      throw new AdapterError(
        "conflict",
        "The Jujutsu repository does not expose a Git backend",
        false,
      );
    }
    gitArgs.unshift(`--git-dir=${gitRoot.stdout.trim()}`);
  }
  const created = await command(
    "git",
    gitArgs,
    repoDir,
  );
  if (!created.success) {
    await Deno.remove(root, { recursive: true });
    throw new AdapterError(
      "temporary",
      `Failed to archive Git revision: ${created.stderr.trim()}`,
      true,
    );
  }
  const extracted = await command(
    "tar",
    ["-xf", archive, "-C", checkout],
    repoDir,
  );
  if (!extracted.success) {
    await Deno.remove(root, { recursive: true });
    throw new AdapterError(
      "temporary",
      `Failed to extract Git revision: ${extracted.stderr.trim()}`,
      true,
    );
  }
  return { root, checkout };
}

export function codexEnvironment(): Record<string, string> {
  const names = [
    "HOME",
    "PATH",
    "CODEX_HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "TMPDIR",
    "USER",
    "LANG",
    "TERM",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
  ];
  return Object.fromEntries(
    names.flatMap((name) => {
      const value = Deno.env.get(name);
      return value ? [[name, value]] : [];
    }),
  );
}

export function codexPermissionArguments(): string[] {
  return [
    "--disable",
    "apps",
    "--disable",
    "multi_agent",
    "-c",
    'default_permissions="openfirma-planning"',
    "-c",
    'permissions.openfirma-planning.filesystem={":minimal"="read",":workspace_roots"={"."="read"}}',
    "-c",
    'approval_policy="never"',
    "-c",
    'history.persistence="none"',
    "-c",
    "memories.generate_memories=false",
    "-c",
    "memories.use_memories=false",
    "-c",
    'web_search="disabled"',
  ];
}

async function runCodex<T>(input: {
  repoDir: string;
  revision: string;
  vcs: "jj" | "git";
  binary: string;
  model?: string;
  timeoutSeconds: number;
  prompt: string;
  schema: z.ZodType<T>;
}): Promise<T> {
  let lastError = "No output";
  for (let schemaAttempt = 1; schemaAttempt <= 3; schemaAttempt++) {
    const archived = await archiveRepository(
      input.repoDir,
      input.revision,
      input.vcs,
    );
    try {
      const schemaPath = `${archived.root}/response-schema.json`;
      const outputPath = `${archived.root}/response.json`;
      await Deno.writeTextFile(
        schemaPath,
        JSON.stringify(codexJsonSchema(input.schema)),
      );
      const args = [
        "exec",
        "--ephemeral",
        "--skip-git-repo-check",
        "--ignore-user-config",
        ...codexPermissionArguments(),
        "--color",
        "never",
        "--output-schema",
        schemaPath,
        "--output-last-message",
        outputPath,
        "-C",
        archived.checkout,
      ];
      if (input.model) args.push("--model", input.model);
      args.push("-");
      const envelopeInstruction =
        'Return a top-level JSON object with exactly one field, "result", containing the requested response.';
      const corrective = schemaAttempt === 1
        ? `${input.prompt}\n${envelopeInstruction}`
        : `${input.prompt}\n${envelopeInstruction}\nYour previous response was invalid: ${lastError}. Return corrected JSON only.`;
      const result = await command(
        input.binary,
        args,
        archived.checkout,
        corrective,
        codexEnvironment(),
        input.timeoutSeconds * 1000,
      );
      if (!result.success) {
        const detail = result.stderr.trim() || "Codex exited unsuccessfully";
        throw new AdapterError(
          /auth|login|401|403/i.test(detail) ? "authentication" : "temporary",
          detail,
          !/auth|login|401|403/i.test(detail),
        );
      }
      let raw: string;
      try {
        raw = await Deno.readTextFile(outputPath);
      } catch (error) {
        lastError = `Codex did not write its final response: ${String(error)}`;
        continue;
      }
      try {
        return z.strictObject({ result: input.schema }).parse(JSON.parse(raw))
          .result;
      } catch (error) {
        lastError = String(error);
      }
    } finally {
      await Deno.remove(archived.root, { recursive: true });
    }
  }
  throw new AdapterError(
    "invalid_output",
    `Codex did not produce valid structured output after three attempts: ${lastError}`,
    false,
  );
}

export function codexJsonSchema(schema: z.ZodType): Record<string, unknown> {
  const convert = (value: unknown): unknown => {
    if (Array.isArray(value)) return value.map(convert);
    if (!value || typeof value !== "object") return value;
    return Object.fromEntries(
      Object.entries(value).map(([key, child]) => [
        key === "oneOf" ? "anyOf" : key,
        convert(child),
      ]),
    );
  };
  return convert(
    z.toJSONSchema(z.strictObject({ result: schema }), { reused: "ref" }),
  ) as Record<string, unknown>;
}

export async function runAuthor(input: {
  repoDir: string;
  revision: string;
  vcs: "jj" | "git";
  globalArgs: GlobalArgs;
  prompt: string;
}) {
  return await runCodex({
    ...input,
    binary: input.globalArgs.codexBinary,
    model: input.globalArgs.codexModel,
    timeoutSeconds: input.globalArgs.codexTimeoutSeconds,
    schema: AuthorResultSchema,
  });
}

export async function runReviewer(input: {
  repoDir: string;
  revision: string;
  vcs: "jj" | "git";
  globalArgs: GlobalArgs;
  prompt: string;
}) {
  return await runCodex({
    ...input,
    binary: input.globalArgs.codexBinary,
    model: input.globalArgs.codexModel,
    timeoutSeconds: input.globalArgs.codexTimeoutSeconds,
    schema: ReviewReportSchema,
  });
}
