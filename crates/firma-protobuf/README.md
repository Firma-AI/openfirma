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

## Versioning and publishing

The wire contract is versioned by package (`firma.v1`). Backward-compatible
changes add fields with new tag numbers; existing field numbers are never reused
or renumbered. A breaking change requires a new package version (`firma.v2`).

The crate is part of the OpenFirma source snapshot and is not published
independently from this workspace.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
