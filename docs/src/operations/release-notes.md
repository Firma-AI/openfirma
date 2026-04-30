# Release Notes

## Versioning policy

OpenAuthority uses Semantic Versioning (SemVer). The `firma-proto` crate version
tracks the gRPC wire contract; breaking changes to the protobuf API increment
the major version. The binary crates (`firma-sidecar`, `firma-authority`) have
their own independent SemVer lines and may release on different cadences. A
`CHANGELOG.md` is maintained per crate under each crate's root directory when
present.

## Where to find release notes

- **GitHub Releases**: `https://github.com/Firma-AI/firma-oss/releases` — each
  release includes a changelog summary, pre-built binary assets, and
  checksums.
- **Top-level CHANGELOG**: `CHANGELOG.md` at the repository root records
  cross-crate changes and migration notes.
- **Per-crate changelogs**: `crates/<name>/CHANGELOG.md` for crate-level
  detail.

## Compatibility matrix

| Sidecar | Authority | Status                 |
| ------- | --------- | ---------------------- |
| 0.x     | 0.x       | Supported (same minor) |
| 0.x     | 0.x-1     | Best-effort            |
| 0.x     | <0.x-1    | Not supported          |

The gRPC wire contract (`firma-proto`) is the boundary. A Sidecar and Authority
running the same `firma-proto` minor version are fully supported. One minor
version apart is best-effort. Larger gaps are not supported and may produce
silent enforcement errors or failed pre-flight handshakes.

## Upgrade guidance

Upgrade order: **Authority first, Sidecars second**. After upgrading the
Authority, verify that existing Sidecars successfully reconnect via
`WatchPolicyBundle` before rolling Sidecars forward. Rolling upgrades are
supported within a minor version: Authority and Sidecars can run different patch
versions concurrently without a maintenance window. Cross-major upgrades are
not guaranteed to be backwards-compatible; consult the release notes for the
target major version for migration steps.
