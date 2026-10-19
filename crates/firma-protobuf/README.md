# firma-protobuf

Shared Protobuf/gRPC wire contract for the Firma stack.

This crate owns the `.proto` definitions for the Authority, Sidecar, and audit
wire formats. Its build script generates Rust types and Tonic client/server
stubs under `firma_protobuf::v1`.

## Layout

```text
proto/
└── firma/
    └── v1/
        ├── audit.proto      # audit event streaming
        ├── authority.proto  # AuthorityService: issuance, policy, revocations
        └── types.proto      # shared message types
src/
└── lib.rs                   # re-exports the generated firma.v1 module
build.rs                     # compiles the .proto via tonic-prost-build
```

The `.proto` files are compiled at build time with a vendored `protoc`
(via `protoc-bin-vendored`), so no system `protoc` install is required.
Generated items live under the `v1` module, including both gRPC client and
server stubs:

```rust
use firma_protobuf::v1::{
    ExecutionEnvelope,
    authority_service_client::AuthorityServiceClient,
    authority_service_server::{AuthorityService, AuthorityServiceServer},
};
```

## Development

Run workspace commands from the OpenFirma or Firma Team repository root:

```bash
just fmt
cargo test -p firma-protobuf
cargo clippy -p firma-protobuf --all-targets -- -D warnings
```

## Managed mapping snapshots

`PolicyBundle.mappings` carries an `ActionMappingSnapshot`: the complete
normalized effective rules the Authority publishes. Its `format_version` must be
`1` and `default_protected` must be `true`. A present snapshot with no rules
means no matches; unmatched protected traffic remains denied. An absent snapshot
is the legacy policy-only shape, which Sidecars reject; it is never an implicit
empty snapshot.

Each `ActionMappingRule` carries a full normalized host (including composed
subdomains), an optional uppercase method, an optional path, and a canonical
`firma_core::ActionClass` identifier. Omitted method/path means unrestricted;
present empty values are invalid. A wildcard path (`"*"`) remains distinct from an
omitted path for specificity. Rules keep the Authority's deterministic order on
the wire — the OpenFirma mini-authority publishes authored file and rule order —
and consumers apply OpenFirma's stable specificity ordering.
The canonical mapping domain owns grammar and validation. Protobuf decoding
preserves values and field presence but does not establish validity.

Policy, entity schema, and mappings use the same `PolicyBundle.version` and
`ttl_seconds`. Every update is a complete replacement. Receivers compile and
validate all components before atomically activating a snapshot; reconnects
receive a complete initial snapshot even when `current_version` matches.

`WatchPolicyBundleRequest.supported_capabilities` explicitly advertises
`POLICY_BUNDLE_CAPABILITY_ACTION_MAPPING_SNAPSHOT_V1`. Managed Authorities must
authenticate first, then reject consumers lacking that recognized capability with
gRPC `FAILED_PRECONDITION` before streaming. Empty, unspecified, or unknown-only
lists do not advertise support. Managed Sidecars must also reject absent or
invalid snapshots before readiness, so an old server ignoring the capability
field cannot silently downgrade governance. Advertisement is repeated on every
reconnect and is sent only by a consumer implementing the advertised behavior.

Every Sidecar requires an Authority endpoint, advertises snapshot support, and
validates and compiles the complete bundle before atomic activation; it never
loads authored local mapping files. The local OpenFirma mini-authority is such
an Authority: it loads `[authority].mapping_rules_paths` and publishes complete
snapshots. Canonical snapshot host patterns also support explicit digit/`*`
port suffixes of at most five characters, preserving authored local matchers
such as `localhost:*`. Managed updates have a 16 MiB receive ceiling for the
complete message. An oversized message disconnects the stream without replacing
the accepted snapshot or extending its deadline. See the
[runtime architecture guide](../../docs-site/src/content/docs/concepts/architecture.md)
for configuration and freshness behavior. This crate's compatibility tests prove
serialization and legacy decoding, not runtime enforcement.

## Policy set descriptor

`PolicyBundleUpdate` is the envelope for everything the Authority pushes to
one agent's Sidecar. New data for the agent is added as new fields on the
envelope (descriptive parts) or on `PolicyBundle` (enforcement parts); the
`WatchPolicyBundle` rpc and the envelope are never renamed.

`PolicyBundleUpdate.policy_set` carries a `PolicySetDescriptor` naming the
policy set the bundle was composed from (`policy_set_id`, a `pset_` TypeID,
and `policy_set_version`, the policy set's own version sequence). An absent
descriptor means the serving Authority does not model policy sets, as the
standalone OpenFirma Authority does not. A present descriptor never has an
empty `policy_set_id`. The descriptor is informational: Sidecars keep
reporting `PolicyBundle.version` as `current_version` and never derive
enforcement decisions from it.

## Versioning and publishing

The wire contract is versioned by package (`firma.v1`). Backward-compatible
changes add fields with new tag numbers; existing field numbers are never reused
or renumbered. A breaking change requires a new package version (`firma.v2`).

The crate is part of the OpenFirma source snapshot and is not published
independently from this workspace.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
