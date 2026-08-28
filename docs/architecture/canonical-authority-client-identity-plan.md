# Canonical Authority Client Identity

## Artifact metadata

- Status: Accepted
- Durable locator: `docs/architecture/canonical-authority-client-identity-plan.md`
- Repository revision researched: `67de08653d3d8bc96f96fdeaf4c8d6430453c9d8`
- Task or requirement source: <https://ampcode.com/threads/T-01a042e7-9125-736f-9bdc-ce404c78d707>
- Supersedes: Not applicable
- Amendment: implementation review of candidate `3678ddff` showed that direct
  string interpolation could emit invalid TOML for a certificate identity
  containing a quote. `DEC-003` and `INV-002` now require TOML-aware encoding
  and a syntax-sensitive subprocess regression.

## Goal and acceptance outcomes

- Goal: make `[[clients]]` entries with one required `identity` field the only
  accepted Authority mTLS allow-list representation.
- Observable acceptance outcomes:
  - Authority startup accepts canonical `[[clients]]` entries and continues to
    authorize the same certificate CN or preferred DNS SAN values.
  - `[[authorized]]`, `cn`, `san`, metadata, and unknown top-level fields fail
    parsing before the TLS verifier is constructed.
  - `firma authority issue-client-cert` prints a directly usable canonical
    `[[clients]]` entry for both CN-only and DNS-SAN certificates.
  - User documentation describes only the canonical current format and current
    mTLS behavior.

## Scope

- In scope: the Authority allow-list file parser, canonical test fixtures, the
  client-certificate command's allow-list output, current mTLS documentation,
  and implementation comments that incorrectly describe current fields as
  compatibility-only.
- Out of scope: certificate identity extraction order, certificate issuance,
  TLS chain validation, Authority configuration construction, live allow-list
  reload, and changes to Sidecar TLS settings.
- Assumptions: `identity` remains an exact string match against the first DNS
  SAN or, when absent, the CN. Empty/whitespace identity handling remains
  unchanged because this change removes alternate shapes rather than changing
  identity normalization.
- Open decisions: None.
- Cohesion and split assessment: one vertical contract change owns parsing,
  generated configuration, trust-boundary fixtures, and public documentation;
  splitting any part would leave an intermediate tip that emits or documents a
  representation the runtime rejects.
- Deferred child plans: Not applicable.

## Routing

- Mode: Full.
- Trigger evidence: the allow-list is an externally visible configuration and
  an mTLS authorization trust boundary; malformed input must fail closed.
- Higher-mode triggers checked: stable configuration and trust-boundary
  triggers both require Full planning.
- Downgrade evidence and reason: Not applicable.

## Current behavior and problem

- Owners and entry points:
  - `AuthorizedClientSet::load` owns the standalone allow-list parse boundary.
  - `AllowListClientVerifier::verify_client_cert` consumes the immutable set
    after PKI chain validation.
  - `run_issue_client_cert` prints the operator-facing entry to add.
- Current success and failure outcomes: `AuthorizedClientsFile` accepts both
  canonical `clients` and obsolete `authorized` arrays. The obsolete entries
  accept optional `cn`, `san`, `issued_at`, and `notes`; unknown fields are not
  rejected. The certificate command prints the obsolete form. Parse or I/O
  errors already stop Authority startup.
- Evidence: `crates/firma-authority/src/authorized_clients.rs:AuthorizedClientSet::load`,
  `crates/firma-authority/src/tls_verifier.rs:AllowListClientVerifier::verify_client_cert`,
  `crates/firma/src/services/authority.rs:run_issue_client_cert`, and
  `crates/firma-authority/src/server.rs:Server::try_new`.

## Key decisions and tradeoffs

### `DEC-001`: Enforce one strict allow-list shape at deserialization

- Choice: deserialize a strict top-level file containing only a defaulted
  `clients: Vec<ClientEntry>`; each `ClientEntry` requires `identity` and denies
  unknown fields. Delete the obsolete entry type and traversal.
- Rationale and evidence: the parser is the earliest owner of this standalone
  file contract, and strict Serde rejection prevents `firma authority` from
  constructing a verifier from superseded or misspelled authorization data.
- Consequences and rejected alternatives: old files fail startup with the
  existing path-bearing `ConfigError::ParseError`. Aliases, untagged variants,
  and post-parse migration are rejected because they retain a second public
  representation and weaken typo detection.

### `DEC-002`: Keep certificate identity semantics independent from file shape

- Choice: retain DNS-SAN-first/CN-fallback extraction and exact set lookup;
  change only how the expected string enters the set.
- Rationale and evidence: `extract_identity` and the TLS handshake tests own
  certificate semantics, while this change concerns the configured allow-list
  representation.
- Consequences and rejected alternatives: no certificate or wire behavior
  changes. A new identity newtype is rejected because it would not prevent the
  configuration-shape defect or improve exact-string matching.

### `DEC-003`: Emit and document only current configuration

- Choice: `issue-client-cert` always prints `[[clients]]` plus a TOML-encoded
  `identity` value, and current docs remove version-to-version and obsolete-form
  prose.
- Rationale and evidence: generated snippets and user docs are public entry
  points into the same configuration contract.
- Consequences and rejected alternatives: no migration table, alias notice, or
  alternate example remains; reviewer-facing records may still state that the
  rejected forms are breaking removals.

## Architecture and invariant ownership

- Architecture shape: standalone TOML bytes cross the configuration trust
  boundary in `AuthorizedClientSet::load`; only the validated identity strings
  enter the immutable set; the TLS verifier can continue assuming that every
  configured identity came from the one canonical entry type.

### `INV-001`: Only canonical client entries reach mTLS authorization

- Semantic predicate: if `AuthorizedClientSet::load(path)` succeeds, every
  configured entry came from a `[[clients]]` table containing exactly one
  recognized `identity` field; an obsolete or unknown field cannot contribute
  an authorized identity.
- Primary owner: `crates/firma-authority/src/authorized_clients.rs`.
- Detailed proof: `TRACE-ALLOW-LIST` and the proof-obligation appendix.

### `INV-002`: Generated operator output is accepted by the runtime parser

- Semantic predicate: the allow-list snippet printed for the selected client
  certificate identity has the canonical table/field names consumed by
  `AuthorizedClientSet::load`, is valid TOML for every accepted certificate
  identity string, and contains the verifier-selected SAN or CN.
- Primary owner: `crates/firma/src/services/authority.rs` with the parser as the
  consumption boundary.
- Detailed proof: `TRACE-ISSUE-CLIENT` and the proof-obligation appendix.

- Compatibility, migration, and failure semantics: `DEC-001` intentionally
  rejects superseded forms with the existing path-bearing parse error; there is
  no migration path. `DEC-002` preserves certificate and handshake behavior.
- Durable documentation owner: `docs/security/mtls-playbook.md`, with retrieval
  summary in `docs-site/public/llms.txt`.

## Implementation slices

### Slice 1: Require and generate the canonical Authority client identity

- Production, types, tests, and docs/config: delete obsolete parser types and
  traversal, add strict Serde boundaries, update unit and mTLS fixtures, change
  `issue-client-cert` output and black-box proof, replace public examples and
  version/migration prose, and repair current-purpose implementation comments.
- Affected decisions and traces: `DEC-001`, `DEC-002`, `DEC-003`,
  `TRACE-ALLOW-LIST`, and `TRACE-ISSUE-CLIENT`.
- Proof obligations: `INV-001` and `INV-002`.
- Focused verification: Authority allow-list unit tests; Authority mTLS
  integration tests; `firma` client-certificate CLI integration tests; explicit
  negative parser controls for missing identity, unknown top-level fields, and
  obsolete or unknown client-entry fields; searches for obsolete allow-list
  syntax in runtime, fixtures, and public docs. The subprocess matrix includes a
  quote-bearing CN and parses the emitted snippet before comparing identity.
- Dependencies: the sectioned Sidecar template tip at researched revision
  `67de08653d3d8bc96f96fdeaf4c8d6430453c9d8`.
- Intentionally unsupported: automatic rewrite, aliases, metadata fields, or
  runtime acceptance of obsolete entries.

## Risks and gaps

- Existing risks: obsolete files can silently authorize clients and unknown
  metadata/typos are ignored; generated output steers operators to that shape.
- Planned mitigations: strict parser tests separately cover the rejected root,
  missing identity, unknown top-level fields, and obsolete or unknown entry
  fields, including path-bearing error assertions; existing handshake tests run
  with canonical fixtures.
- Explicit evidence gaps: cross-platform certificate-command behavior is
  exercised on the test host; it uses platform-independent Rust file and PEM
  APIs and has no conditional implementation.
- Least-confident decisions: whether empty identity entries should become an
  error. Existing semantics ignore them, and changing that independent
  normalization contract is excluded.

## Plan-review findings and dispositions

### PLAN-001

- **Severity:** Medium
- **Category:** Trust-boundary verification
- **Classification:** Design risk
- **Evidence:** The plan requires a canonical entry with a required `identity`
  and rejection of unknown top-level fields
  (`canonical-authority-client-identity-plan.md:13-19`, `73-80`, `114-121`).
  However, the detailed proof obligation only explicitly asserts rejection of
  an obsolete root and unknown entry metadata (`:283-286`); it does not require
  negative controls for:
  - `[[clients]]` missing `identity`;
  - unknown top-level keys;
  - obsolete `cn` or `san` fields inside `[[clients]]`.

  At base revision, these inputs cross `AuthorizedClientSet::load` through
  `toml::from_str` before authorization state is constructed
  (`crates/firma-authority/src/authorized_clients.rs:31-62,89-116`).
- **Reachable path and outcome:** Authority startup → `build_mtls_future` →
  `AuthorizedClientSet::load` → TOML deserialization → verifier construction.
  An implementation can satisfy the broadly worded planned tests while
  accidentally omitting strictness on one Serde boundary, allowing an unknown
  field or failing to establish that `identity` is mandatory.
- **Invariant owner / trust boundary:** `AuthorizedClientSet::load`; `INV-001`,
  where operator-controlled TOML becomes mTLS authorization state.
- **Practical impact:** A regression in strict parsing could silently accept
  misspelled or obsolete authorization configuration, contrary to the breaking
  fail-closed requirement.
- **Correction:** Expand the `INV-001` proof matrix to require individual
  negative tests for missing `identity`, unknown top-level fields, and `cn`,
  `san`, and metadata/other unknown fields within `[[clients]]`. Each should
  assert `ConfigError::ParseError` with the allow-list path. Retain a canonical
  positive control and the startup call-path evidence showing no verifier is
  constructed after parse failure.
- **Confidence:** High.
- **Unverified assumptions:** Assumes “required identity field” means syntactic
  presence, while preserving the plan's explicit decision to continue ignoring
  empty or whitespace-only identity values.

#### Disposition

- Status: Corrected.
- Rationale: the slice verification, risk mitigation, and detailed proof matrix
  now enumerate each strictness boundary and require the returned parse error to
  retain the configured allow-list path. `Server::try_new` already propagates
  `AuthorizedClientSet::load` failure before it constructs the verifier; the
  focused tests exercise the boundary owner directly.
- Incorporated at: Slice 1 focused verification, Risks and gaps, and the
  `INV-001` configuration proof obligation.
- Decided by: planner.

## Final verification

- Focused checks: `firma-authority` passed 110 tests; the targeted
  `issue-client-cert` CLI subprocess regression passed; strict syntax searches
  found obsolete allow-list forms only in rejection assertions.
- Workspace checks: `just check` passed all 2,594 tests with 34 skipped at the
  final candidate, plus formatting, clippy, doctests, build, audit, dependency
  policy, and release checks. One initial process-orchestrator timeout passed in
  isolation before the clean full rerun. `just docs-build` built 311 pages at
  the preceding production/docs-equivalent candidate.
- Post-implementation independent review: the final exact candidate
  `3ecb18b272a7be8dad5fdb8f68a5a67b46a06aac` received no actionable findings
  after the three findings below were corrected and re-reviewed.

## Post-implementation independent review

The implementation received four independent exact-candidate reviews. The
first reviewed `3678ddff`, the second reviewed `6b127ab0`, and the final review
before CI reviewed `2ff04c31`. After correcting the Windows subprocess fixture,
the final review covered the complete base-to-candidate range
`67de08653d3d8bc96f96fdeaf4c8d6430453c9d8..3ecb18b272a7be8dad5fdb8f68a5a67b46a06aac`.

### `IMPL-001` — Medium — Generated CN-only allow-list entry is not always valid TOML

- **Evidence:** `crates/firma/src/services/authority.rs:338,347-348` and
  `crates/firma/src/args/authority.rs:94-98` at candidate `3678ddff`.
  `--cn` accepted an unrestricted string, but the selected identity was
  interpolated directly into a quoted TOML value. For example, a CN containing
  `"` produced a malformed snippet.
- **Impact:** the output violated `INV-002`: a successfully issued certificate
  could be paired with generated configuration that the Authority rejected.
- **Correction:** encode the identity through `toml::Value::String` and add a
  quote-bearing black-box case that parses the emitted snippet before comparing
  the recovered identity.

Disposition: corrected in `6b127ab02305b129ae81d671e41b01d41f86fc24`.
The accepted plan was explicitly amended at `DEC-003`, `INV-002`, and the
subprocess proof obligation. Independent re-review verified the TOML-aware
encoding and regression.

### `IMPL-002` — Low — Client certificate rotation guidance is inaccurate

- **Evidence:** `docs/security/mtls-playbook.md:112-116` at candidate
  `6b127ab0` claimed an old same-identity certificate would stop working after
  an Authority restart with a new allow-list.
- **Impact:** the allow-list matches identity strings rather than certificate
  serial numbers, so both valid same-identity certificates remain authorized
  until expiry or removal of their issuing CA.
- **Correction:** document the same-identity limitation and the new-identity or
  CA-rotation paths for invalidating an old certificate before expiry.

Disposition: corrected in `2ff04c31dd31a81b35740d10132e5182526cde6d`.
The final independent review verified the operational guidance and reported no
remaining correctness, trust-boundary, test, documentation, or plan-conformance
finding.

### `IMPL-003` — Windows CI — Generated CA paths were not valid TOML

- **Evidence:** the Windows `Check` job for candidate `a549671c` failed in
  `issue_client_cert_prints_canonical_allow_list_entries` because direct path
  interpolation left Windows backslashes unescaped in the test's generated
  `firma.toml`.
- **Impact:** Windows CI could not exercise the canonical generated-entry
  contract even though production identity encoding was portable.
- **Correction:** encode each generated CA path through `toml::Value::String`
  before embedding it in the subprocess configuration.

Disposition: corrected in `3ecb18b272a7be8dad5fdb8f68a5a67b46a06aac`.
The targeted subprocess test passed locally. Fresh independent review confirmed
that the path serialization is portable across supported path syntax and found
no remaining actionable issue in the complete exact candidate. Windows CI is
the final platform proof.

#### Fresh exact-candidate review record

> ## Review target
>
> - Workspace: `/home/user/workspace/pr611`
> - HEAD/candidate confirmed: `3ecb18b272a7be8dad5fdb8f68a5a67b46a06aac`
> - Base confirmed: `67de08653d3d8bc96f96fdeaf4c8d6430453c9d8`
> - Working tree was clean.
> - Reviewed the complete 12-file base-to-candidate diff and accepted plan.
>
> ## Findings
>
> **None.** No remaining actionable correctness, security, documentation, or test issues found.
>
> The Windows correction at `crates/firma/tests/integration/authority_client_cert.rs:21-32` is portable for supported paths: `toml::Value::String` emits quoted TOML with Windows backslashes and other special characters escaped. Production identity output uses the same safe mechanism at `crates/firma/src/services/authority.rs:347-348`.
>
> The strict parser correctly rejects alternate roots and unknown/missing entry fields, while preserving DNS-SAN-first/CN-fallback authorization. Documentation accurately describes identity-based authorization, restart requirements, and the limits of identity-based certificate revocation.
>
> ## Verification
>
> - `cargo nextest run -p firma-authority` — **110/110 passed**
> - `dprint check <all changed Rust/Markdown/TXT files>` — **passed**
> - Targeted CLI test command could not complete because the orb filesystem ran out of space during compilation; no test failure was observed.
>
> ## Assumptions / residual limits
>
> - Windows CI was not executable in this Linux orb; portability was established by tracing TOML serialization semantics and the subprocess test construction.
> - Non-Unicode OS paths are outside TOML’s string representation; ordinary Windows Unicode paths, including drive separators/backslashes, are handled correctly.

## Technical evidence

### Applicability assessment

| Section                     | Applicability  | Reason or evidence                                                   |
| --------------------------- | -------------- | -------------------------------------------------------------------- |
| Vocabulary                  | Applicable     | File entry identity and certificate identity must remain distinct.   |
| Alternatives                | Applicable     | Strict parse, aliases, and migration are plausible boundaries.       |
| File-tree diff              | Applicable     | A CLI integration test file may be added to own subprocess behavior. |
| Type and signature sketches | Not applicable | Existing private Serde types and immutable set preserve ownership.   |
| Semantic call traces        | Applicable     | Configuration and generated output cross runtime/trust boundaries.   |
| Trust analysis              | Applicable     | The file determines which mTLS clients reach Authority RPCs.         |
| Detailed proof obligations  | Applicable     | Strict failure and handshake preservation require multiple suites.   |

### Vocabulary

| Canonical term       | Meaning                                                       | Owner/context   | Terms to avoid                 | Conflict or decision                  |
| -------------------- | ------------------------------------------------------------- | --------------- | ------------------------------ | ------------------------------------- |
| Client entry         | One `[[clients]]` table with required `identity`              | Allow-list file | authorized entry, cn/san entry | `DEC-001` selects one shape.          |
| Certificate identity | First DNS SAN, otherwise CN, extracted from a verified client | TLS verifier    | client entry                   | `DEC-002` preserves extraction order. |

### Alternatives

- Strict deserialization at `AuthorizedClientSet::load` is selected because it
  is the earliest boundary and gives existing path-bearing startup failures.
- Serde aliases or untagged old/new entry variants would preserve multiple
  representations and typo ambiguity, violating the requested canonical-only
  contract.
- A separate migration command or raw TOML traversal would let another public
  entry point accept obsolete authorization data; it is unnecessary in an
  alpha product and is rejected.

### File-tree diff

```diff
crates/firma-authority/src/authorized_clients.rs         # strict parser/tests
crates/firma-authority/src/tls_verifier.rs               # canonical fixture
crates/firma-authority/tests/integration/e2e_mtls.rs     # canonical handshake fixture
crates/firma/src/services/authority.rs                   # canonical CLI output
crates/firma/tests/integration/main.rs                   # register subprocess proof
+crates/firma/tests/integration/authority_client_cert.rs # CLI output proof
crates/firma-config-schema/src/sidecar/authority.rs      # current-purpose comment
crates/firma-sidecar/src/config/authority.rs             # current-purpose comment
docs/security/mtls-playbook.md                           # canonical current guide
docs-site/public/llms.txt                                # canonical retrieval summary
```

### Semantic call traces

| Field                      | Content                                                                                                                                                     |
| -------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Trace ID                   | `TRACE-ALLOW-LIST`                                                                                                                                          |
| State                      | Proposed                                                                                                                                                    |
| Entry and stimulus         | Authority starts with `authorized_clients_path`.                                                                                                            |
| Path                       | `Server::try_new` → `AuthorizedClientSet::load` → strict TOML decode → immutable set → `AllowListClientVerifier::verify_client_cert` → handshake allow/deny |
| Input/output types         | file bytes → private `AuthorizedClientsFile` → `HashSet<String>` → `ClientCertVerified`/TLS error                                                           |
| Validation/trust crossings | Serde strictness establishes file shape; web PKI validates the certificate before exact allow-list lookup.                                                  |
| Invariant established      | `INV-001` at successful `load`.                                                                                                                             |
| Invariant assumed          | Verifier assumes each set member is an operator-configured exact identity.                                                                                  |
| Success outcome            | A chain-valid client whose selected identity is present reaches gRPC.                                                                                       |
| Failure path               | I/O/TOML errors fail startup; unlisted identities fail TLS handshake.                                                                                       |
| Evidence                   | `authorized_clients.rs`, `server.rs`, `tls_verifier.rs`, `e2e_mtls.rs`.                                                                                     |
| Proof boundary             | Parser unit tests plus mTLS integration suite.                                                                                                              |
| Unknowns                   | None.                                                                                                                                                       |

| Field                      | Content                                                                                                                                        |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| Trace ID                   | `TRACE-ISSUE-CLIENT`                                                                                                                           |
| State                      | Proposed                                                                                                                                       |
| Entry and stimulus         | Operator invokes `firma authority issue-client-cert` with CN and optional DNS SAN.                                                             |
| Path                       | CLI parse → certificate generation → selected SAN-or-CN identity → canonical snippet on stdout → operator allow-list file → `TRACE-ALLOW-LIST` |
| Input/output types         | CLI strings → X.509 certificate + PEM files + TOML text → private parser types                                                                 |
| Validation/trust crossings | rcgen validates SAN encoding; allow-list parser validates copied TOML.                                                                         |
| Invariant established      | `INV-002` by fixed canonical output plus parser contract.                                                                                      |
| Invariant assumed          | The operator copies the printed entry without changing the identity.                                                                           |
| Success outcome            | Printed snippet names the same identity selected by the verifier.                                                                              |
| Failure path               | Invalid CA material or SAN fails before success output.                                                                                        |
| Evidence                   | `services/authority.rs`, CLI integration test, `tls_verifier.rs`.                                                                              |
| Proof boundary             | `firma` subprocess test plus Authority parser tests.                                                                                           |
| Unknowns                   | None.                                                                                                                                          |

### Trust analysis

- Actors and authority: the operator controls the allow-list and client CA;
  Sidecars present certificates; the Authority decides whether a verified
  certificate identity may reach gRPC.
- Protected asset: Authority policy/revocation streams and issuance RPCs behind
  mandatory mTLS authentication.
- Hostile input: malformed or crafted allow-list TOML and unlisted or
  chain-invalid client certificates.
- Trust transitions: untrusted file bytes become configured authorization data
  only after strict deserialization; untrusted peer certificates become an
  extracted identity only after web-PKI chain validation.
- Reachable abuse path addressed: an obsolete/unknown field can no longer be
  silently interpreted or ignored while constructing authorization state.
- Unchanged limits: authorization remains exact string matching and the file is
  read once at startup; certificate revocation remains allow-list removal plus
  certificate rotation/expiry.

### Detailed proof obligations

| Invariant | Kind                | Owner/proof boundary             | Suite/boundary      | Stimulus                                                                                                                       | Observable effects                                                                              | Failure cases                                                                                                        | Status   | Slice | Limits                                                                      |
| --------- | ------------------- | -------------------------------- | ------------------- | ------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- | -------- | ----- | --------------------------------------------------------------------------- |
| `INV-001` | Trust/configuration | `AuthorizedClientSet::load`      | unit                | canonical TOML; obsolete root; missing identity; unknown top-level field; `cn`, `san`, or unknown metadata under `[[clients]]` | canonical identities load                                                                       | every noncanonical case returns `ConfigError::ParseError` carrying the configured path, before verifier construction | Verified | 1     | Direct parser proof; startup propagation is existing control-flow evidence. |
| `INV-001` | Trust/runtime       | `AllowListClientVerifier`        | integration         | canonical allow-list plus allowed/unlisted/no-cert/wrong-CA peers                                                              | only chain-valid, listed identity reaches policy stream                                         | all other peers fail before gRPC success                                                                             | Verified | 1     | Does not prove CLI text.                                                    |
| `INV-002` | CLI/configuration   | `run_issue_client_cert` + parser | subprocess and unit | issue CN-only, quote-bearing CN, and DNS-SAN certificates                                                                      | emitted snippet parses as TOML and contains only `[[clients]]`/`identity` for selected identity | obsolete table/field names absent; generation errors have no success snippet                                         | Verified | 1     | Does not automate copying stdout into a deployment.                         |
