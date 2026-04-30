# firma-sidecar release binary dependency snapshot

Placeholder — populated by `scripts/snapshot-binary-deps.sh` on each
release host.

Run from the repo root after `cargo build --release -p firma-sidecar`:

```bash
./scripts/snapshot-binary-deps.sh
```

The script overwrites this file with the host's `otool -L` (macOS) or
`ldd` (Linux) output plus a captured timestamp. Commit the updated
file so reviewers can see runtime-dependency drift.
