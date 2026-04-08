---
id: 001-file-policy-source
unit: 003-policy-revocation
intent: 006-sidecar-proxy-enforcement
status: draft
priority: must
created: 2026-04-05T12:00:00Z
assigned_bolt: null
implemented: false
---

# Story: 001-file-policy-source

## User Story

**As an** operator
**I want** the Sidecar to load Cedar policies from a directory and hot-reload when files change
**So that** I can update policies without restarting the Sidecar

## Acceptance Criteria

- [ ] **Given** a configured policy directory containing valid `.cedar` files, **When** the Sidecar starts, **Then** all `.cedar` files in that directory are loaded, compiled into a Cedar policy set, and made available to the enforcement pipeline
- [ ] **Given** the Sidecar is running with a valid policy bundle, **When** a `.cedar` file in the watched directory is added, modified, or removed, **Then** the filesystem change is detected and a new compiled bundle is hot-reloaded within 500ms
- [ ] **Given** the configured policy directory contains one or more malformed `.cedar` files, **When** the Sidecar starts, **Then** it refuses to start (fail-fast) with a clear error message identifying the malformed file(s)
- [ ] **Given** the Sidecar is running with a valid policy bundle, **When** a filesystem change introduces a malformed `.cedar` file, **Then** the malformed bundle is rejected with a logged error and the last valid bundle is retained
- [ ] **Given** the `PolicySource` trait is defined, **When** a community developer implements it, **Then** they can provide custom policy source backends without modifying the Sidecar
- [ ] **Given** a policy bundle is loaded (at startup or via hot-reload), **When** the bundle is activated, **Then** the bundle version is tracked and available for inclusion in audit events

## Technical Notes

- Implement the `PolicySource` trait for a `FilePolicySource` struct
- Use the `notify` crate for cross-platform filesystem watching (inotify on Linux, kqueue on macOS)
- Use the `cedar-policy` crate to compile `.cedar` files into a `PolicySet`
- Hot-reload should use atomic swap (e.g., `Arc<RwLock<PolicySet>>` or `arc_swap`) to avoid blocking in-flight evaluations during reload
- Bundle version for file mode can be derived from a hash of file contents + modification timestamps
- Only files with the `.cedar` extension should be loaded; other files in the directory are ignored
- Subdirectories should not be recursively scanned (flat directory only in V1)
- File mode is the default when `--authority-url` is not configured
- File mode is explicitly a temporary mechanism for development/testing while the Mini Authority (intent 005) is not yet complete

## Dependencies

### Requires

- `cedar-policy` crate for policy compilation
- `notify` crate for filesystem watching
- `PolicySource` trait definition (defined in this story or in firma-core)

### Enables

- 002-grpc-policy-source (shares the `PolicySource` trait and bundle swap mechanism)
- Unit 002-enforcement-pipeline Stage 2 (consumes the compiled policy bundle)
- Unit 006-audit-observability (bundle version included in audit events)

## Edge Cases

| Scenario | Expected Behavior |
| -------- | ----------------- |
| Policy directory does not exist at startup | Fail-fast with clear error: directory not found |
| Policy directory is empty (no `.cedar` files) | Fail-fast with clear error: no policies found |
| Policy directory contains only non-`.cedar` files | Fail-fast with clear error: no policies found |
| Two `.cedar` files define conflicting policies | Cedar compiler resolves per its semantics (forbid overrides permit); no Sidecar-level conflict resolution |
| Filesystem event fires but file is still being written (partial write) | Debounce filesystem events (e.g., 50ms) to avoid reading partially written files |
| Filesystem watcher fails or is not supported | Log error and fall back to periodic polling (configurable interval, default 5s) |
| Very large number of `.cedar` files (>1000) | Compilation may take longer; log warning if compilation exceeds 500ms; no hard cap in V1 |
| File permissions prevent reading a `.cedar` file | Treat as malformed: fail-fast at startup, reject on hot-reload |
| Symlinked `.cedar` files in the directory | Follow symlinks and load the target file normally |

## Out of Scope

- gRPC-based policy sourcing (story 002)
- Policy evaluation logic (unit 002-enforcement-pipeline)
- Cedar schema validation (`.cedarschema` enforcement is part of the enforcement pipeline)
- Recursive subdirectory scanning
- Policy file encryption or signing
- Remote file sources (S3, HTTP, etc.)
