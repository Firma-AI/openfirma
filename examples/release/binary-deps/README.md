# Release Binary Dependency Snapshot

This example records the shared-library dependencies of the release
`firma-sidecar` binary for a reference host.

```bash
cargo build --release -p firma-sidecar
examples/release/binary-deps/snapshot.sh
```

The script writes the snapshot to `docs/release/binary-deps.md` so release
reviewers can see dependency drift.
