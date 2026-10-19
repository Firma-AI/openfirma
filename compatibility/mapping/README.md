# Mapping Compatibility Corpus

This directory records the mapping behavior that the managed Authority and the
OpenFirma Sidecar must share. It is data-only so both the private and public
workspace components can consume the same source without introducing a public
dependency on private crates.

`cases.toml` was captured from OpenFirma at revision
`a737ed612b8f16019f1cf3e58012af6d512bba50`.

## Contract Layers

The corpus separates behavior into two layers:

- **Observed behavior** describes the current OpenFirma parser, validator,
  normalizer, matcher, and selectable mapping catalog. Consumers must run these cases
  against both the Sidecar and Authority implementations.
- **Agreed behavior** describes the mapping-set representation selected for
  central management. It includes explicit owner hosts, dotless relative
  subdomains, base-host rules, and overlap detection. This representation does
  not yet exist in the current Sidecar.

Do not change an observed expectation to make a new implementation pass. First
confirm that OpenFirma behavior intentionally changed, update its owning tests,
and record the new source revision. Changes to agreed behavior require a product
contract update.

## Sources

The behavior is owned by these production paths:

- `crates/firma-authority/src/mappings.rs` parses authored mapping files
  selected by `[authority].mapping_rules_paths`, rejects duplicate identities,
  and builds the published snapshot.
- `crates/firma-core/src/mapping.rs` defines authored-host validation, host
  normalization, canonical rule validation, and specificity.
- `crates/firma-sidecar/src/normalizer/mapping.rs` compiles published snapshots
  and defines matching and default protection.
- `crates/firma-sidecar/src/normalizer/mod.rs` defines request host and path
  normalization before matching.
- `crates/firma-secret-provider/src/glob.rs` defines `*` matching.
- `crates/firma-sidecar/src/enforcement/registry.rs` defines current Sidecar
  action-class validation.
- `crates/firma/src/args/config.rs` defines the 11 selectable mapping templates.
- `crates/firma/templates/mappings/` contains those template rules.

Paths are relative to the exported OpenFirma repository root.
Agreed cases cite sections in this document, which is the durable exported
record of the product contract.

## Fixture Schema

The top-level `schema_version` versions this corpus, not the user-facing mapping
format. Consumers must reject unsupported corpus versions.

Every case has a stable `id`, a `contract` value, and a `source` reference:

- `contract = "observed"` locks down current executable behavior.
- `contract = "agreed"` describes the central mapping-set contract.

Expected failures use stable fixture error codes instead of implementation error
strings. Test runners map their typed errors to these codes.

### Parse Cases

`parse_cases` contain complete TOML documents. `outcome` is `accept` or
`reject`. Accepted cases may specify the deserialized rule count. Rejected cases
identify the parsing boundary with `error_code`.

Parsing and validation are separate. For example, `TRACE` is accepted by the
TOML method parser but rejected by mapping validation.

### Validation Cases

`validation_cases` contain complete parseable mapping documents and exercise
file, field, duplicate, and action-class validation. `error_code` identifies the
first expected failure.

Empty effective rule lists are valid protected deny-all snapshots. Private
mapping definitions still require at least one rule. The Authority's
authored-file parser accepts unknown fields, trims and normalizes host
spelling, and treats `path = ""` as an omitted path before publication;
published snapshots use the stricter canonical rule language in
`firma-core::mapping`.

Duplicate identity is the normalized tuple `(method, host, path)`. An omitted
path and an empty path share the same duplicate key, while an omitted path and
`path = "*"` do not.

### Normalization Cases

`host_normalization_cases` map authored host patterns to the current matching
form. Current normalization:

- trims surrounding whitespace;
- lowercases ASCII host text;
- removes DNS trailing dots;
- removes ports `80` and `443` for matching;
- preserves other all-digit ports; and
- treats bracketed IPv6 separately from DNS and IPv4 authorities.

`path_normalization_cases` describe request-path normalization. Rule paths are
not normalized when loaded.

### Glob and Match Cases

`glob_cases` prove that `*` matches any sequence, including dots and path
separators. There is no escape syntax, single-character wildcard, character
class, DNS-label boundary, or path-segment boundary.

`match_cases` contain complete rule TOML and one request. `target` identifies
whether to stop after `mapping_table` matching or run the full
`intent_normalizer`. Expected results are:

- `matched` with an `action_class`;
- `unclassified_protected`;
- `normalization_denied` after a table match that cannot be represented in an
  execution envelope.

Tables are always protected by default; constructors reject an unprotected
default instead of returning passthrough for unmatched traffic.

The mapping-file validator accepts only the eight configured methods, but a
runtime request can carry another syntactically valid method. Such a request
matches an any-method rule because omission means any `Method`, not only the
eight methods accepted in mapping files. The full normalizer then denies the
request because its execution-envelope method enum has the same eight-method
limit.

### Precedence Cases

`precedence_cases` lock down the current additive specificity behavior. The
score is:

- 100 for a host without `*`;
- 10 for a specified method;
- 5 for a present path;
- one per nonempty slash-separated path segment; and
- 10 for a path without `*`.

Rules are stable-sorted by descending score. Authored order breaks equal-score
ties. This is not lexicographic precedence: a wildcard-host rule with enough
path segments can outrank an exact-host rule.

### Decomposition Cases

`decomposition_cases` describe the agreed conversion from a full host pattern
to one explicitly selected owner host and a dotless relative subdomain.
Decomposition never infers a registrable domain.

The `full_host`, `owner_host`, and `subdomain` fields form a candidate tuple.
Accepted cases also record normalized and recomposed outputs. Rejected cases
identify the violated tuple invariant.

Composition is deterministic:

- An empty subdomain produces the normalized owner host.
- Otherwise, insert `.` between the subdomain and the owner's DNS name.
- Preserve a nondefault owner port after the composed DNS name.
- IPv4, bracketed IPv6, and bare catch-all owners require an empty subdomain.

For example, owner `example.com` plus subdomain `api` produces
`api.example.com`; users never write `.api` or `api.`. The fixture's explicit
owner selection is part of the standard catalog contract.

Owner hosts are concrete: DNS names use strict label syntax, IPv6 literals
are bracketed, ports are numeric `1-65535`, and `*` appears only as the bare
catch-all (optionally with a port). Partial wildcards such as
`*.example.com` are not valid owners; wildcard coverage belongs in
subdomains. An empty rule path is rejected; omit the path to match any path.

### Overlap Cases

`overlap_cases` describe the agreed host-coverage check between mapping sets.
This is stronger than current OpenFirma duplicate detection. The cases are
direction-independent: reversing `left` and `right` must produce the same
result. Managed mapping sets additionally reject non-identical but
intersecting effective hosts with the same method and path, since unrelated
sets have no defined cross-set precedence.

### Catalog Inventory

`catalogs` inventory all 11 values exposed by `Mapping::CONFIG_CHOICES` and all
266 rules. They contain 64 template-local host entries representing 59 globally
distinct normalized patterns. The empty, non-selectable `custom.toml` scaffold
is excluded.

Each distinct normalized source pattern has an explicitly reviewed `owner_host`
and dotless `subdomain`. Patterns from different templates may share an owner;
Conflicting effective tuples must be curated before those sources merge into
generated host sets.

## Consumer Requirements

Each executable consumer must:

- parse this file with strict unknown-field rejection;
- reject duplicate case IDs across all sections;
- run every case for its supported contract layer;
- report the case ID on failure;
- verify all expected template paths and rule counts; and
- verify the catalog totals declared under `catalog_summary`.

The public export must include this directory unchanged.
