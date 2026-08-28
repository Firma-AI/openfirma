# Canonical Capability File Handoff

## Artifact metadata

- Status: Accepted
- Durable locator: `docs/architecture/canonical-capability-file-plan.md`
- Repository revision researched: `a549671c3a620b332d36e784a23d1983480d15d7`
- Task or requirement source:
  <https://ampcode.com/threads/T-01a042e7-9125-736f-9bdc-ce404c78d707>
- Supersedes: the capability-file slice from the deleted broad #614 plan; this
  artifact owns the independently split vertical change.

## Goal and acceptance outcomes

- Goal: make canonical `firma_core::CapabilitySeed` TOML the only file format
  accepted by `firma run --capability-file`, while preserving the distinct
  token and path roles in the existing runtime handoff.
- Observable acceptance outcomes:
  - An Authority-issued seed is parsed before Run prepares a sandbox or local
    component, and only its `raw_token` enters `FIRMA_CAPABILITY_TOKEN`.
  - `FIRMA_CAPABILITY_FILE` retains the originally configured path exactly.
  - A locally autostarted Sidecar receives the same file path in its existing
    `[sidecar.capability_seed].paths` synthesis; a pre-managed external Sidecar
    remains independently configured.
  - Plain tokens, malformed TOML, missing fields, unknown fields, and empty
    `raw_token` values fail closed in Run with path-bearing errors that do not
    print seed contents. Shared-format failures in Sidecar startup and reload
    are equally secret-safe.
  - Public documentation describes only the canonical signed seed TOML flow
    from `firma authority issue` to `firma run` and the local/external Sidecar
    distinction.

## Scope

- In scope: the shared `CapabilitySeed` deserialization contract, Run's
  file-source read boundary, exact environment construction, local Sidecar path
  synthesis fixtures, Sidecar startup/reload parse-error sanitization,
  external-Sidecar behavior proof, fail-before-effects regressions, and
  current-product capability-file documentation.
- Out of scope: the signed protobuf TTL request, capability issuance, token
  claim or signature verification policy, agent/session identity semantics,
  automatic capability refresh, Sidecar reloader lifecycle or map-retention
  behavior, and seed path confinement. The next stacked PR owns canonical
  filesystem containment.
- Assumptions:
  - The file's structured claims remain descriptive until the Sidecar verifies
    `raw_token` and checks that its signed claims match the seed claims.
  - A pre-managed external Sidecar owns its own capability map; Run preserving
    the source path and exporting `raw_token` does not configure that Sidecar.
  - `FIRMA_CAPABILITY_FILE` intentionally preserves the configured path rather
    than a canonicalized path; Sidecar confinement owns safe resolution before
    local reads and watcher registration.
- Open decisions: None.
- Cohesion and split assessment: this is one vertical file-to-runtime handoff.
  Splitting shared schema strictness, Run parsing, environment separation, or
  current docs would leave an intermediate tip that accepts or documents a
  different representation. Filesystem confinement remains independently
  stackable because this tip preserves existing path routing and read/watch
  behavior.
- Deferred child plan:
  `docs/architecture/capability-seed-confinement-plan.md` will own canonical
  directory/path resolution, traversal/symlink rejection, and resolved-path
  watcher registration.

## Routing

- Mode: Full.
- Trigger evidence: `--capability-file` is a public CLI/configuration contract
  and crosses a capability-token trust boundary into both the agent environment
  and local Sidecar configuration.
- Higher-mode triggers checked: stable external behavior, secret handling, and
  authorization-boundary input all require Full planning.
- Downgrade evidence and reason: Not applicable.

## Current behavior and problem

- Owners and entry points:
  - `firma_run::capability::read_capability_token` reads a file as UTF-8,
    trims the whole document, and returns it as an opaque token string.
  - `runtime::execute_run` invokes that read before `backend.prepare`.
  - `runtime::build_execution_env` exports the returned string as
    `FIRMA_CAPABILITY_TOKEN` and independently exports the configured path as
    `FIRMA_CAPABILITY_FILE`.
  - For local Sidecar autostart, `execute_run` threads the configured path via
    `AutostartFlags.capability_seed_path` to
    `sidecar::config::configure_capability_seed`.
  - `firma_sidecar::startup::capability::load_capability_map` parses the shared
    `CapabilitySeed`, verifies `raw_token`, and compares all file claims with
    verified signed claims. `CapabilityReloader` repeats the same load and is
    spawned by the production Sidecar startup path.
- Current success and failure outcomes: a canonical seed file is exported in
  full as `FIRMA_CAPABILITY_TOKEN`; a plain token file is accepted; empty and
  unreadable files fail before backend preparation. Serde currently ignores
  unknown `CapabilitySeed` fields. Local Sidecar startup later parses and
  verifies the same file, while an external Sidecar owns its own seed list.
- Problem: Run's opaque-string read creates an incompatible second file
  representation and can expose the entire signed TOML document where only the
  token is expected. It also allows plain-token input to bypass canonical
  structure at the public CLI boundary.
- Disproven concern: production Sidecar hot reload is active. `run_start`
  invokes `spawn_capability_reload` after building the pipeline runtime and
  before interceptor readiness. This change does not modify the reloader.

## Key decisions and tradeoffs

### `DEC-001`: Deserialize the shared seed type at Run's earliest file boundary

- Choice: replace the opaque read/trim operation with
  `toml::from_str::<firma_core::CapabilitySeed>` inside
  `read_capability_token`, before backend or component preparation, and return
  only `seed.raw_token`.
- Rationale and evidence: this is the existing one-shot file boundary and call
  order already precedes `build_backend(...).prepare(...)`. Reusing the shared
  type avoids a Run-specific seed representation.
- Consequences and rejected alternatives: plain token files and malformed or
  incomplete TOML fail before runtime effects. A local wrapper duplicating all
  fields, parsing to `toml::Value`, or extracting `raw_token` without the other
  required fields is rejected because each creates a weaker second schema.

### `DEC-002`: Make the canonical shared representation strict

- Choice: apply Serde unknown-field denial to `CapabilitySeed`. Run rejects an
  empty `raw_token` after deserialization before exporting it.
- Rationale and evidence: the shared type is the canonical Authority-written,
  Run-read, and Sidecar-read representation. Strictness at that type prevents
  Run and Sidecar from diverging and makes misspellings fail closed.
- Consequences and rejected alternatives: an unknown field now fails at every
  shared seed parse. A Run-only strict wrapper is rejected as duplicate schema;
  prefix-only PASETO checks are rejected because downstream cryptographic
  verification remains authoritative and a prefix check would not prove token
  validity.

### `DEC-003`: Keep token material and source path as separate values

- Choice: preserve `CapabilitySource::File { path }` unchanged. Export only the
  parsed `raw_token` as `FIRMA_CAPABILITY_TOKEN`, export the original path as
  `FIRMA_CAPABILITY_FILE`, and continue routing that path into local Sidecar
  synthesis.
- Rationale and evidence: token consumers require a token string, while the
  local Sidecar requires a file it can parse, verify, and watch. The configured
  path is also the current operator-visible environment contract.
- Consequences and rejected alternatives: no new handoff struct is needed; the
  current token return value and profile-owned path already separate roles.
  Re-serializing or copying a seed is rejected because it creates another file
  and changes refresh/watch semantics.

### `DEC-004`: Preserve downstream authorization and refresh ownership

- Choice: do not validate signatures or claim equality in the Run parser and
  do not change refresh logic. The local Sidecar continues to verify the token,
  compare all claims, and hot-reload the file. File sources continue to suppress
  Run-managed mint and refresh. External Sidecars remain independently seeded.
- Rationale and evidence: `seed_into_entry` owns cryptographic verification and
  exact claim comparison; `CapabilityRefresher` owns only Run-minted seeds.
  Duplicating either behavior at a format boundary would split authority and
  require key/topology changes beyond this fix.
- Consequences and rejected alternatives: a structurally canonical file with
  an invalid token can pass Run parsing but remains fail-closed at the existing
  authorization boundary. Run-side signature verification and file-source
  refresh are rejected as redesigns.

### `DEC-005`: Report safe, path-bearing parse failures

- Choice: map file I/O and TOML failures to `RunError::Capability` with the
  configured path and Sidecar parse failures to `anyhow::Error` with the seed
  path and a concise format reason; do not interpolate file content or TOML
  source excerpts. Preserve enough parser category/location context to identify
  the bad file.
- Rationale and evidence: a capability seed contains a bearer token. Standard
  TOML error display may include source excerpts, which must not reach logs or
  terminal output. Shared strictness creates newly reachable Sidecar startup and
  reload errors, so each file-reading consumer must sanitize at its boundary.
- Consequences and rejected alternatives: users receive a useful path and
  structural reason but not the offending line. Sidecar keeps its existing
  startup failure and reload-log/map-retention behavior. Forwarding the complete
  TOML parser display in either consumer is rejected as a secret-disclosure
  risk.

## Architecture and invariant ownership

- Architecture shape: Authority and Run issuance produce the one shared seed
  type on disk. Run's file boundary deserializes that type, separates token from
  path, and performs no authorization. The wrapped process receives the token
  and original path. A local Sidecar independently reads the same path through
  its existing shared-type parser, verifies the signature and claim equality,
  and watches it; an external Sidecar is not configured by Run.

```diagram
┌─────────────────┐  CapabilitySeed TOML  ┌────────────────────────────┐
│ Authority issue │──────────────────────▶│ Run file parse (pre-effect)│
└─────────────────┘                       └─────────────┬──────────────┘
                                                     │
                        ┌────────────────────────────┴──────────────────┐
                        │                                               │
                        ▼                                               ▼
              ┌─────────────────────┐                       ┌─────────────────────┐
              │ wrapped process env │                       │ local Sidecar config│
              │ TOKEN = raw_token   │                       │ paths = source path │
              │ FILE = source path  │                       └──────────┬──────────┘
              └─────────────────────┘                                  │
                                                                       ▼
                                                            ┌─────────────────────┐
                                                            │ verify + claim match│
                                                            │ load + hot reload   │
                                                            └─────────────────────┘
```

### `INV-001`: Only canonical seed TOML crosses Run's file boundary

- Semantic predicate: if `read_capability_token(File { path })` succeeds, the
  complete file deserialized as the strict shared `CapabilitySeed`, its
  `raw_token` is non-empty, and the returned value equals that field exactly.
- Primary owner: `crates/firma-run/src/capability/mod.rs`, with structural
  strictness owned by `crates/firma-core/src/capability_seed.rs`.
- Detailed proof: `TRACE-FILE-PARSE` and the proof-obligation appendix.

### `INV-002`: Token and file-document material are not confused

- Semantic predicate: for a file source, `FIRMA_CAPABILITY_TOKEN` equals only
  the seed's exact `raw_token`, while `FIRMA_CAPABILITY_FILE` equals the original
  configured path; no environment value intended as a token contains the seed
  TOML document.
- Primary owner: `crates/firma-run/src/runtime/mod.rs`.
- Detailed proof: `TRACE-ENV` and the proof-obligation appendix.

### `INV-003`: Rejected input produces no sandbox or component effects

- Semantic predicate: an invalid capability file returns an error before
  `SandboxBackend::prepare`, `resolve_authority`, or
  `prepare_network_runtime` can create backend/runtime/component artifacts.
- Primary owner: call order in `runtime::execute_run`.
- Detailed proof: `TRACE-FAIL-CLOSED` and the proof-obligation appendix.

### `INV-004`: Existing cryptographic and topology ownership remains intact

- Semantic predicate: this change neither authorizes a parsed seed nor alters
  its claim/session/agent bindings. A local Sidecar still verifies `raw_token`,
  compares every signed claim to the file, and watches the routed path; a file
  source still suppresses Run mint/refresh; an external Sidecar receives no
  seed-list mutation from Run.
- Primary owner: `firma-sidecar::startup::capability`,
  `firma-run::routing`, and `firma::services::sidecar`.
- Detailed proof: `TRACE-LOCAL` and `TRACE-EXTERNAL`.

### `INV-005`: Seed parse failures do not disclose seed material

- Semantic predicate: Run and Sidecar structural parse errors identify the
  configured seed path and safe failure category without including
  `raw_token`, any source excerpt, or the complete seed document. Sidecar reload
  retains the previous capability map and logs only the sanitized error.
- Primary owner: `firma-run::capability::read_capability_token` and
  `firma-sidecar::startup::capability::load_capability_map`.
- Detailed proof: `TRACE-FAIL-CLOSED` and `TRACE-LOCAL`.

- Failure semantics: unreadable, malformed, incomplete, unknown-field,
  plain-token, and empty-token files fail with a path-bearing capability error
  before launch. Structurally valid but cryptographically invalid seeds retain
  existing downstream denial.
- Durable documentation owners: `docs/configuration.md`, `docs/cli.md`, and the
  docs-site capability and Run guides; `docs-site/public/llms.txt` carries the
  concise retrieval contract.

## Implementation slices

### Slice 1: Canonicalize the capability-file handoff

- Production, types, tests, and docs/config:
  - make the shared `CapabilitySeed` Serde boundary strict;
  - parse it in Run's existing file reader, reject an empty `raw_token`, and
    return only the exact token with safe path-bearing errors;
  - sanitize Sidecar startup/reload structural parse errors at its existing
    file-reading boundary without changing verification or reload behavior;
  - replace plain-token fixtures with canonical Authority-shaped seed TOML;
  - prove exact token/path environment values for local and external Sidecar
    selection, local synthesis path preservation, and no document exposure;
  - prove plain, malformed, missing-field, unknown-field, empty-token, missing,
    and non-UTF-8 inputs fail before backend/component artifacts;
  - prove Sidecar startup/reload structural failures retain path/category and
    previous-map behavior without exposing a token, source excerpt, or document;
  - update current public docs without migration or legacy guidance.
- Affected decisions and traces: all decisions; `TRACE-FILE-PARSE`,
  `TRACE-ENV`, `TRACE-FAIL-CLOSED`, `TRACE-LOCAL`, and `TRACE-EXTERNAL`.
- Proof obligations: all invariants.
- Focused verification: shared core seed tests; `firma-run` capability lease,
  runtime, routing, and config integration tests; Sidecar seed startup/reload
  tests; targeted CLI/subprocess regression for pre-effect rejection; strict
  public-doc and fixture searches.
- Dependencies: canonical Authority client identity tip
  `a549671c3a620b332d36e784a23d1983480d15d7`.
- Intentionally unsupported: plain-token files, aliases, partial seed TOML,
  unknown fields, Run-side signature verification, Run-managed refresh for file
  sources, or external Sidecar seed injection.

## Risks and mitigations

- A parser error could print the bearer token through a source excerpt. Sanitize
  at both Run and Sidecar file-reading boundaries and test startup/reload as
  well as Run for absence of the token and full document.
- Returning a trimmed token could mutate signed bytes. Return `raw_token`
  exactly and use trimming only to detect empty/whitespace-only input.
- A test that calls only the parser would not prove lifecycle ordering. Exercise
  `execute_run` in a subprocess with a deterministic backend-effect canary and
  assert rejection occurs before it appears.
- Local and external topology can be conflated. Cover both selections: local
  synthesis receives the preserved path; external mode exports token/path but
  leaves Sidecar seed configuration untouched.
- Shared strictness could break an internal fixture that relied on ignored
  fields. Run all shared seed, Sidecar load/reload, issuance, and end-to-end
  capability suites.
- Claim metadata might be mistaken for authorization performed by Run. Keep
  cryptographic checks exclusively in the existing Sidecar owner and describe
  that boundary accurately.
- Explicit evidence gap: external Sidecar behavior is proved at Run's routing
  and environment boundary; the external process is intentionally not
  reconfigured or started by this change.
- Least-confident decision: the most useful safe TOML error detail supported by
  the pinned parser API. Implementation may retain only parser category and
  source position if a stable message-only API is unavailable; it must not
  include source excerpts.

## Plan-review findings and dispositions

### `PLAN-001` — High / Security / Confirmed conflict

**Finding:** The plan does not preserve secret-safe errors across every parser affected by shared strictness.

**Evidence and reachable path:**

- `DEC-002` makes `firma_core::CapabilitySeed` strict for every consumer (`canonical-capability-file-plan.md:120-132`).
- The trust requirement says errors must not echo token or document content (`:415-424`), but implementation and proof obligations sanitize only Run errors (`:134-147`, `:274-296`, `:393-395`, `:431-439`).
- At base `a549671…`, Sidecar startup parses the shared alias with:
  - `crates/firma-sidecar/src/startup/capability.rs:56-61`
  - `toml::from_str(&body)` followed by formatting the complete TOML parser `Display`.
- Reload failures then log that error at `capability.rs:241-263`.
- Reachable path: local or independently configured external Sidecar → startup/reload reads malformed or newly rejected unknown-field seed → TOML diagnostic is embedded in `anyhow` → startup output or reload log may contain a source excerpt, including bearer-token/document material.

**Invariant owner / boundary:** Shared `CapabilitySeed` deserialization changes the accepted schema, while each file-reading consumer owns secret-safe error conversion. Run alone cannot own the Sidecar logging boundary.

**Impact:** The proposed shared strictness can create newly reachable rejection diagnostics in Sidecar startup/reload without proving the stated non-disclosure invariant. A secret-safe Run test cannot establish safety for those consumers.

**Required correction:** Amend the plan to do one of the following:

1. Include sanitized Sidecar seed parse errors in this slice and require startup plus reload tests proving token, source excerpt, and complete document are absent while the path and safe category remain; or
2. Explicitly narrow the non-disclosure outcome to Run, record existing Sidecar parser disclosure as a security gap with an owned follow-up, and avoid claiming shared parser-error safety.

The first option best matches the stated trust invariant without changing Sidecar verification or reload ownership.

**Confidence:** High.

**Assumptions:** TOML diagnostics may include source excerpts, as the plan itself recognizes at lines 274-275. I did not execute a candidate implementation because this was planning-only review.

#### Disposition

- Status: Corrected.
- Rationale: the accepted plan now includes secret-safe parse conversion at the
  Sidecar's existing file-reading boundary and startup/reload non-disclosure
  controls. This keeps shared strictness coherent without changing token
  verification, watcher lifecycle, or previous-map retention.
- Incorporated at: acceptance outcomes, Scope, `DEC-005`, `INV-005`, Slice 1,
  Risks and mitigations, and `PROOF-009`.
- Decided by: planner.

> Independent Full-plan review against base `a549671c3a620b332d36e784a23d1983480d15d7` found one actionable issue: `PLAN-001` (High, Security, confirmed conflict). Applying strict deserialization to shared `firma_core::CapabilitySeed` affects Sidecar startup and reload parsing, but the plan sanitizes and tests only Run parser errors. The existing Sidecar path formats the complete TOML parser error and logs reload failures, so malformed or newly rejected input can expose source excerpts or bearer-token/document content. Before acceptance, either include secret-safe Sidecar parse-error conversion and startup/reload non-disclosure proofs in this slice, or explicitly narrow the invariant and preserve the Sidecar disclosure gap as an owned follow-up. Reviewer-authored wording must remain unchanged; dispositions may be appended. Pre-implementation review does not replace exact-tip post-implementation review.

> Focused follow-up Full-plan review against base `a549671c3a620b332d36e784a23d1983480d15d7` confirms that the correction fully resolves `PLAN-001`. The accepted plan now sanitizes shared `CapabilitySeed` structural parse failures at both Run and Sidecar file-reading boundaries and requires startup and reload proofs excluding bearer tokens, source excerpts, and complete seed documents while retaining safe path/category diagnostics. It preserves existing Sidecar verification, watcher lifecycle, reload logging outcome, and previous-map retention behavior. No new actionable planning finding or design incoherence was identified. Pre-implementation review does not replace exact-tip post-implementation review.

## Final verification

- Focused checks: dprint; core seed tests; `firma-run` capability lease,
  routing, runtime, and config tests; Sidecar seed load/reload tests; targeted
  black-box lifecycle proof; canonical documentation searches.
- Workspace checks: `just check` and `just docs-build`.
- Post-implementation independent review: required for Rust correctness,
  trust-boundary behavior, secret-safe errors, local/external topology,
  regression coverage, and public-doc accuracy.

## Technical evidence

### Applicability assessment

| Section                     | Applicability | Reason or evidence                                                 |
| --------------------------- | ------------- | ------------------------------------------------------------------ |
| Vocabulary                  | Applicable    | Token, seed document, and source path have distinct roles.         |
| Alternatives                | Applicable    | Shared strict parse and local extraction are plausible choices.    |
| File-tree diff              | Applicable    | Core, Run, focused tests, and current docs own the vertical slice. |
| Type and signature sketches | Applicable    | Existing function returns the extracted token without new types.   |
| Semantic call traces        | Applicable    | Input crosses file, env, topology, and verification boundaries.    |
| Trust analysis              | Applicable    | The file contains a bearer token and authorization metadata.       |
| Detailed proof obligations  | Applicable    | Failure ordering and topology preservation require control tests.  |

### Vocabulary

| Canonical term   | Meaning                                                | Owner/context       |
| ---------------- | ------------------------------------------------------ | ------------------- |
| Capability seed  | Complete strict `CapabilitySeed` TOML document         | Shared file schema  |
| Raw token        | Exact `raw_token` string carried by the seed           | Agent/Sidecar token |
| Source path      | Configured path to the seed document                   | Run profile/routing |
| Local Sidecar    | Sidecar autostarted and configured by this Run         | Run topology        |
| External Sidecar | Pre-managed Sidecar whose seed list Run does not alter | External topology   |

### Alternatives

- Selected: strict deserialization on the shared type at Run's existing read
  boundary. It proves the complete current shape and keeps one representation.
- Rejected: parse a `toml::Value` and extract `raw_token`; this accepts partial
  or misspelled metadata that the local Sidecar later rejects.
- Rejected: define a private Run seed struct; this duplicates the canonical
  schema and can drift.
- Rejected: pass the parsed seed through runtime as a new wrapper; token and
  path are already independently owned, so a new type adds no invariant.
- Rejected: verify signatures during the Run read. That duplicates the
  Sidecar's authorization owner and cannot be topology-independent without
  broadening key resolution.

### File-tree diff

- Modify `crates/firma-core/src/capability_seed.rs` for strict shared
  deserialization and a rejection control.
- Modify `crates/firma-run/src/capability/mod.rs` for canonical parse and safe
  extraction, and `crates/firma-sidecar/src/startup/capability.rs` for
  secret-safe shared-format parse errors.
- Modify `crates/firma-run/tests/integration/capability_lease.rs` and focused
  runtime/routing tests for format, environment, lifecycle, and topology proof.
- Modify only capability-file user docs under the crate READMEs, `docs/`, docs
  site, and `llms.txt`; do not include future confinement claims in this PR.

### Type and signature sketches

```rust
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitySeed {/* existing fields */}

pub fn read_capability_token(source: &CapabilitySource) -> Result<Option<String>, RunError>;
```

No public signature changes and no new production type are required.

### Semantic call traces

#### `TRACE-FILE-PARSE`: successful canonical file

1. `execute_run` resolves one profile and obtains `CapabilitySource::File`.
2. `read_capability_token` reads UTF-8 bytes from the configured path.
3. Strict shared deserialization requires every canonical field and rejects
   unknown fields.
4. Empty `raw_token` is rejected; otherwise its exact string is returned.

#### `TRACE-ENV`: launch environment

1. `execute_run` retains the extracted token separately from the profile.
2. `build_execution_env` sets `FIRMA_CAPABILITY_TOKEN` to that exact token.
3. The profile-owned file source sets `FIRMA_CAPABILITY_FILE` to the original
   configured path.
4. No seed serialization or document string enters the token value.

#### `TRACE-FAIL-CLOSED`: malformed or noncanonical file

1. The read or strict parse fails at `read_capability_token`.
2. A safe `RunError::Capability` contains the configured path and reason but no
   source excerpt or seed material.
3. `execute_run` returns before `resolve_working_dir`, backend construction and
   preparation, Authority resolution, Sidecar synthesis, or agent launch.

#### `TRACE-LOCAL`: local Sidecar

1. Run parses the file for its environment token.
2. The unchanged `CapabilitySource::File` path populates
   `AutostartFlags.capability_seed_path`.
3. Sidecar synthesis adds that path to `[sidecar.capability_seed].paths`.
4. Sidecar startup parses the shared seed with secret-safe structural errors,
   verifies the raw token, compares all claims, and registers its existing hot
   reloader.
5. A structural reload error logs only the sanitized path/category and retains
   the previous map.

#### `TRACE-EXTERNAL`: external Sidecar

1. Run parses the file and builds exact token/path environment values.
2. External routing neither synthesizes local Sidecar config nor adds a seed
   path to the external Sidecar.
3. The external Sidecar's own seed configuration remains authoritative.

### Trust and secret analysis

- Trusted inputs: none at the file boundary; all seed file content is
  operator-controlled and potentially sensitive.
- Validation boundary: strict structural validation occurs in Run; signature,
  claim-equality, expiry, agent, and session authorization remain in Sidecar.
- Secret transport: only `raw_token` enters the secret environment variable;
  errors must not echo token/document content.
- Failure default: every read/parse/extraction failure aborts before runtime
  effects. Downstream verification failures continue to deny capability use.
- Boundary non-change: file path confinement is explicitly deferred but the
  path remains available for that next owner; protocol and TLS behavior are
  unchanged.

### Detailed proof obligations

| ID          | Invariant | Required evidence                                                                                                                       |
| ----------- | --------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `PROOF-001` | `INV-001` | Authority-shaped seed returns exact `raw_token`; plain, malformed, incomplete, unknown-field, empty-token, and non-UTF-8 fixtures fail. |
| `PROOF-002` | `INV-001` | Shared-type test proves unknown fields fail for all consumers; Sidecar load/reload and Authority issuance suites pass.                  |
| `PROOF-003` | `INV-002` | Local and external profile controls assert exact `TOKEN` and original `FILE`; token value excludes the TOML document.                   |
| `PROOF-004` | `INV-003` | Subprocess `execute_run` control asserts invalid input returns before a backend/runtime artifact can be created.                        |
| `PROOF-005` | `INV-004` | Local synthesis test receives original path; file source still suppresses mint/Run refresher; production reloader call remains.         |
| `PROOF-006` | `INV-004` | External control proves no local synthesis/configuration while exact environment handoff remains.                                       |
| `PROOF-007` | all       | Focused tests, full `just check`, docs build, strict searches, and fresh independent exact-tip review pass.                             |
| `PROOF-008` | lifecycle | Accepted plan is first PR commit; review record directly precedes mechanical plan deletion; plan is absent at tip/diff.                 |
| `PROOF-009` | `INV-005` | Run and Sidecar startup/reload parser controls retain path/category but exclude token, source excerpt, and full document.               |

## Atomic revision and review lifecycle

1. Commit this accepted, independently reviewed plan as the first PR-owned
   revision.
2. Add one coherent implementation revision containing the shared schema,
   Run boundary, exact lifecycle/topology tests, and current-product docs.
3. Run focused and full verification and obtain fresh independent review of the
   exact candidate.
4. Record the immutable review evidence and every finding disposition in this
   plan in one documentation revision.
5. Mechanically delete exactly this plan in the immediately following closing
   revision.

The final branch tip and PR diff contain no plan Markdown. Immutable commit
locators retain the accepted plan, plan review, implementation review, and
dispositions after deletion.
