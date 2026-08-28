# Canonical Authority Client Identity

## Artifact metadata

- Status: Accepted
- Durable locator: `docs/architecture/canonical-authority-client-identity-plan.md`
- Repository revision researched: `67de08653d3d8bc96f96fdeaf4c8d6430453c9d8`
- Task or requirement source: <https://ampcode.com/threads/T-01a042e7-9125-736f-9bdc-ce404c78d707>
- Supersedes: Not applicable

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

- Choice: `issue-client-cert` always prints `[[clients]]` plus `identity`, and
  current docs remove version-to-version and obsolete-form prose.
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
  `AuthorizedClientSet::load` and contains the verifier-selected SAN or CN.
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
  syntax in runtime, fixtures, and public docs.
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

- Focused checks: formatter; `cargo nextest run -p firma-authority`; targeted
  `firma` CLI integration tests; strict syntax search.
- Workspace checks: `just check` and `just docs-build`.
- Post-implementation independent review: required for Rust correctness,
  trust-boundary behavior, regression coverage, and public-doc accuracy.

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

| Invariant | Kind                | Owner/proof boundary             | Suite/boundary      | Stimulus                                                                                                                       | Observable effects                                                  | Failure cases                                                                                                        | Status                  | Slice | Limits                                                                      |
| --------- | ------------------- | -------------------------------- | ------------------- | ------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- | ----------------------- | ----- | --------------------------------------------------------------------------- |
| `INV-001` | Trust/configuration | `AuthorizedClientSet::load`      | unit                | canonical TOML; obsolete root; missing identity; unknown top-level field; `cn`, `san`, or unknown metadata under `[[clients]]` | canonical identities load                                           | every noncanonical case returns `ConfigError::ParseError` carrying the configured path, before verifier construction | Planned                 | 1     | Direct parser proof; startup propagation is existing control-flow evidence. |
| `INV-001` | Trust/runtime       | `AllowListClientVerifier`        | integration         | canonical allow-list plus allowed/unlisted/no-cert/wrong-CA peers                                                              | only chain-valid, listed identity reaches policy stream             | all other peers fail before gRPC success                                                                             | Existing fixture update | 1     | Does not prove CLI text.                                                    |
| `INV-002` | CLI/configuration   | `run_issue_client_cert` + parser | subprocess and unit | issue CN-only and DNS-SAN certificates                                                                                         | stdout contains only `[[clients]]`/`identity` for selected identity | obsolete table/field names absent; generation errors have no success snippet                                         | Planned                 | 1     | Does not automate copying stdout into a deployment.                         |
