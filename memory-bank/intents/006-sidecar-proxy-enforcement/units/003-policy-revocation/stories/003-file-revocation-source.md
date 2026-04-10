---
id: 003-file-revocation-source
unit: 003-policy-revocation
intent: 006-sidecar-proxy-enforcement
status: draft
priority: must
created: 2026-04-05T12:00:00Z
assigned_bolt: null
implemented: false
---

# Story: 003-file-revocation-source

## User Story

**As an** operator
**I want** revocation entries loaded from a JSON file with filesystem watching
**So that** I can revoke tokens by editing a file without Authority dependency

## Acceptance Criteria

- [ ] **Given** a configured revocation JSON file exists, **When** the Sidecar starts, **Then** all revocation entries are loaded and used to populate the bloom filter and LRU cache (story 005)
- [ ] **Given** the Sidecar is running, **When** the revocation JSON file is modified, **Then** the filesystem change is detected and the revocation cache (bloom filter + LRU) is updated with the new entries
- [ ] **Given** the `RevocationSource` trait is defined, **When** a community developer implements it, **Then** they can provide custom revocation source backends without modifying the Sidecar
- [ ] **Given** revocation entries are loaded from the JSON file, **When** the cache is updated, **Then** both new additions and the full set of entries are reflected in the bloom filter and LRU cache

## Technical Notes

- Implement the `RevocationSource` trait for a `FileRevocationSource` struct
- Use the `notify` crate for filesystem watching (same as story 001)
- JSON file format should be a simple array of revocation entries, each containing at minimum: `token_id` (string), `revoked_at` (ISO 8601 timestamp), and optional `reason` (string)
- Example JSON format:
  ```json
  {
    "revocations": [
      {
        "token_id": "tok_abc123",
        "revoked_at": "2026-04-05T10:30:00Z",
        "reason": "compromised"
      }
    ]
  }
  ```
- On file change, the entire file is re-read and the bloom filter is rebuilt (bloom filters do not support deletion; a rebuild is required when entries are removed)
- The LRU cache is updated incrementally: new entries added, removed entries evicted
- Debounce filesystem events (e.g., 50ms) to avoid reading partially written files
- File mode is the default for revocation when `--authority-url` is not configured
- This source pushes updates into the shared revocation cache (story 005); it does not own the cache

## Dependencies

### Requires

- 005-revocation-cache (provides the bloom filter + LRU cache to populate)
- `RevocationSource` trait definition (defined in this story or in firma-core)
- `notify` crate for filesystem watching

### Enables

- Unit 002-enforcement-pipeline Stage 1 (reads the revocation cache for token revocation checks)

## Edge Cases

| Scenario | Expected Behavior |
| -------- | ----------------- |
| Revocation file does not exist at startup | Start with an empty revocation cache; log warning (no revocations is a valid state) |
| Revocation file is empty or contains an empty array | Start with an empty revocation cache; no error |
| Revocation file contains malformed JSON | At startup: log error, start with empty cache (revocation is best-effort from file source); on hot-reload: retain current cache, log error |
| Revocation file contains duplicate `token_id` entries | Deduplicate; use the most recent `revoked_at` timestamp; no error |
| Revocation file is very large (>100k entries) | Bloom filter rebuild may be slow; log warning if rebuild exceeds 100ms; no hard cap |
| File permissions prevent reading the revocation file | Log error; start with or retain empty/current cache |
| Revocation entry has a `revoked_at` timestamp in the future | Accept the entry (clock skew tolerance); the token is treated as revoked |
| File is replaced atomically (rename/move) | Filesystem watcher detects the change and triggers reload |

## Out of Scope

- gRPC-based revocation sourcing (story 004)
- Revocation cache implementation details (story 005)
- Token validation logic (unit 002-enforcement-pipeline)
- Revocation entry expiry / TTL (entries persist until removed from the file)
- Revocation file encryption or signing
