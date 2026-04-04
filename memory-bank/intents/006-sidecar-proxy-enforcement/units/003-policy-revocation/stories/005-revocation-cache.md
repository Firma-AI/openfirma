---
id: 005-revocation-cache
unit: 003-policy-revocation
intent: 006-sidecar-proxy-enforcement
status: draft
priority: must
created: 2026-04-05T12:00:00Z
assigned_bolt: null
implemented: false
---

# Story: 005-revocation-cache

## User Story

**As the** enforcement pipeline (Stage 1)
**I want** O(1) revocation checks with no network I/O
**So that** token revocation checking doesn't add measurable latency

## Acceptance Criteria

- [ ] **Given** a token ID that has not been revoked, **When** checked against the bloom filter, **Then** the bloom filter returns a negative result in sub-microsecond time (< 1us)
- [ ] **Given** a token ID that has been revoked, **When** checked against the bloom filter, **Then** the bloom filter returns a positive result (may be a false positive)
- [ ] **Given** a bloom filter positive (potential match), **When** confirmed against the LRU cache, **Then** the LRU cache returns the confirmed revocation entry or indicates the bloom filter result was a false positive
- [ ] **Given** a revocation check request, **When** the two-layer check executes, **Then** the check order is: bloom filter first (fast negative), then LRU cache for confirmation on positive results only
- [ ] **Given** the revocation cache is being checked, **When** the check executes, **Then** no network I/O occurs (all data is in-memory)
- [ ] **Given** multiple threads are concurrently checking and updating the cache, **When** reads and writes happen simultaneously, **Then** the cache is thread-safe with no data races or deadlocks

## Technical Notes

- The revocation cache is a two-layer structure:
  1. **Layer 1 - Bloom filter**: Probabilistic data structure for O(1) negative checks. A negative result definitively means "not revoked." A positive result means "possibly revoked" and requires confirmation.
  2. **Layer 2 - LRU cache**: Deterministic cache of confirmed revocations. Used only when the bloom filter returns positive to confirm or deny the match.
- Use a bloom filter crate (e.g., `bloomfilter`, `probabilistic-collections`, or a custom implementation) with a configurable false positive rate (default target: 0.1% at expected capacity)
- Use an LRU cache crate (e.g., `lru`) with configurable capacity (default: 100,000 entries)
- The bloom filter does not support deletion. When the file revocation source (story 003) removes entries, the bloom filter must be rebuilt. The gRPC source (story 004) only adds entries, so no rebuild is needed for gRPC mode.
- Thread safety: use `Arc<RwLock<...>>` or a lock-free structure. Reads (revocation checks) are far more frequent than writes (source updates), so a read-biased concurrency strategy is preferred.
- The cache exposes a simple interface:
  - `is_revoked(token_id: &str) -> bool` — the two-layer check
  - `add_revocation(token_id: &str, entry: RevocationEntry)` — called by sources
  - `rebuild(entries: &[RevocationEntry])` — called by file source on full reload
- Bloom filter sizing: for 100,000 expected entries at 0.1% false positive rate, the bloom filter requires approximately 144 KB of memory
- The cache must be created at Sidecar startup and shared (via `Arc`) between the revocation sources and the enforcement pipeline

## Dependencies

### Requires

- None (foundational data structure; does not depend on specific sources)

### Enables

- 001-file-policy-source (not directly, but shares design patterns for atomic swap)
- 003-file-revocation-source (populates the cache from file)
- 004-grpc-revocation-source (populates the cache from gRPC stream)
- Unit 002-enforcement-pipeline Stage 1 (reads the cache for revocation checks)

## Edge Cases

| Scenario | Expected Behavior |
| -------- | ----------------- |
| Bloom filter false positive (bloom says revoked, but LRU has no entry) | `is_revoked` returns `false`; the token is not revoked; this is the expected behavior for false positives |
| Cache is empty (no revocations loaded yet) | All `is_revoked` checks return `false`; bloom filter has no bits set |
| LRU cache reaches capacity | Oldest entries evicted per LRU policy; bloom filter retains them (may cause increased false positives confirmed as negative by LRU miss); log warning when capacity reached |
| Bloom filter capacity significantly exceeded | False positive rate degrades; log warning; consider triggering a rebuild with a larger bloom filter |
| Concurrent `rebuild` (file source) while reads are in progress | Rebuild creates a new bloom filter and swaps atomically; in-flight reads complete against the old filter; new reads use the new filter |
| Concurrent `add_revocation` (gRPC source) while reads are in progress | Write lock acquired briefly for the LRU insert; bloom filter add is typically atomic or uses a brief lock; reads may briefly block but contention should be minimal |
| Token ID is empty string | Return `false` (not revoked); empty string is not a valid token ID |
| Very long token ID (>1 KB) | Accepted; hashed by bloom filter regardless of input length |

## Out of Scope

- Revocation source implementations (stories 003, 004)
- Token validation logic beyond revocation checking (unit 002-enforcement-pipeline)
- Persistent storage of revocation cache to disk
- Cache warming from a snapshot on startup (sources handle initial population)
- Distributed cache synchronization between multiple Sidecar instances
- Bloom filter auto-scaling (fixed capacity in V1; operator configures expected size)
