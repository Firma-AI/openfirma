---
unit: 003-policy-revocation
intent: 006-sidecar-proxy-enforcement
phase: inception
status: draft
created: 2026-04-05T12:00:00Z
updated: 2026-04-05T12:00:00Z
---

# Unit Brief: Policy & Revocation Sources

## Purpose

Implement dual-mode data sources for Cedar policy bundles and token revocation lists. File-based mode enables standalone operation and development/testing in isolation. gRPC streaming mode connects to the Mini Authority for production deployments. Includes the two-layer revocation cache for O(1) negative checks.

## Scope

### In Scope

- `PolicySource` trait with two implementations (file, gRPC)
- File mode: load all `.cedar` files from directory, filesystem watch, hot-reload (atomic swap)
- File mode: fail-fast on malformed files at startup; retain last valid on hot-reload failure
- gRPC mode: `WatchPolicyBundle` server-streaming client, initial bundle + incremental updates
- gRPC mode: TTL enforcement (default 30s), fail-closed on TTL expiry (`POLICY_BUNDLE_STALE`)
- gRPC mode: reconnect with full bundle push
- Bundle version tracking (included in audit events)
- `RevocationSource` trait with two implementations (file, gRPC)
- File mode: load revocation entries from JSON file, filesystem watch
- gRPC mode: `WatchRevocations` server-streaming client
- Two-layer revocation cache: bloom filter (O(1) negative) + LRU (confirmed positives)
- Revocation propagation < 1s p99

### Out of Scope

- Policy evaluation logic (owned by 002-enforcement-pipeline)
- Token validation logic (owned by 002-enforcement-pipeline; reads this unit's cache)
- Authority server implementation (separate intent 005)

---

## Assigned Requirements

| FR | Requirement | Priority |
|----|-------------|----------|
| FR-5 | Policy Source (Dual-Mode) | Must |
| FR-6 | Revocation Source (Dual-Mode) | Must |

---

## Domain Concepts

### Key Entities

| Entity | Description | Attributes |
|--------|-------------|------------|
| PolicyBundle | Compiled Cedar policy set | policies, version, loaded_at |
| RevocationCache | Two-layer cache for revocation checks | bloom_filter, lru_cache |
| BundleVersion | Version identifier for policy bundles | version_string, timestamp |
| PolicySourceConfig | Configuration for policy source mode | mode (file/grpc), path/url, ttl |

### Key Operations

| Operation | Description | Inputs | Outputs |
|-----------|-------------|--------|---------|
| load_policies | Load and compile Cedar policies | Directory path or gRPC stream | PolicyBundle |
| hot_reload | Swap policy bundle atomically | New bundle | Old bundle replaced |
| check_revocation | O(1) revocation check | Token ID | Revoked (bool) |
| update_revocations | Update cache from source | Revocation events | Updated bloom filter + LRU |

---

## Story Summary

| Metric | Count |
|--------|-------|
| Total Stories | 5 |
| Must Have | 5 |
| Should Have | 0 |
| Could Have | 0 |

### Stories

| Story ID | Title | Priority | Status |
|----------|-------|----------|--------|
| 001-file-policy-source | Load .cedar files, watch, hot-reload, malformed rejection | Must | Planned |
| 002-grpc-policy-source | WatchPolicyBundle stream, incremental updates, TTL/fail-closed | Must | Planned |
| 003-file-revocation-source | JSON file-based revocation with filesystem watch | Must | Planned |
| 004-grpc-revocation-source | WatchRevocations stream, bloom filter + LRU updates | Must | Planned |
| 005-revocation-cache | Bloom filter + LRU two-layer cache for O(1) checks | Must | Planned |

---

## Dependencies

### Depends On

| Unit | Reason |
|------|--------|
| firma-proto (intent 003) | gRPC service definitions: `WatchPolicyBundle`, `WatchRevocations` |
| firma-core (intent 002) | Trait definitions for `PolicyBundleStore`, `RevocationStore` |

### Depended By

| Unit | Reason |
|------|--------|
| 002-enforcement-pipeline | Stage 1 reads revocation cache, Stage 2 reads policy bundle |

### External Dependencies

| System | Purpose | Risk |
|--------|---------|------|
| cedar-policy crate | Policy compilation | Low |
| tonic | gRPC client | Low |
| Mini Authority (runtime) | Policy + revocation source (gRPC mode) | Medium — optional dependency |

---

## Technical Context

### Suggested Technology

- cedar-policy for policy compilation
- tonic for gRPC streaming client
- notify crate for filesystem watching
- bloom filter crate (e.g., `bloomfilter` or custom)
- LRU cache (e.g., `lru` crate)

### Integration Points

| Integration | Type | Protocol |
|-------------|------|----------|
| Mini Authority | gRPC client | WatchPolicyBundle, WatchRevocations streams |
| Filesystem | File watch | inotify/kqueue via notify crate |
| Enforcement Pipeline | Internal | In-memory shared references |

---

## Constraints

- File mode exists as temporary testing mechanism (not long-term operational mode)
- gRPC mode activated when `--authority-url` is configured
- TTL default 30s; on expiry → fail-closed (DENY all with POLICY_BUNDLE_STALE)
- Malformed `.cedar` at startup → fail-fast; malformed during hot-reload → retain last valid
- Bloom filter must provide sub-microsecond negative checks
- Revocation propagation < 1s p99
- Policy hot-reload < 500ms

---

## Success Criteria

### Functional

- [ ] File mode loads all .cedar files and compiles at startup
- [ ] File mode hot-reloads within 500ms of filesystem change
- [ ] Malformed files: fail-fast at startup, retain valid on hot-reload
- [ ] gRPC mode receives initial bundle and applies incremental updates
- [ ] gRPC mode: TTL expiry triggers fail-closed
- [ ] Bloom filter provides sub-microsecond negative revocation check
- [ ] LRU stores confirmed revocations
- [ ] Revocation propagation < 1s p99
- [ ] Both traits allow community implementations

### Non-Functional

- [ ] Policy hot-reload < 500ms
- [ ] Bloom filter check < 1us

### Quality

- [ ] Tests for malformed policy files (startup + hot-reload)
- [ ] Tests for TTL expiry and fail-closed behavior
- [ ] Tests for bloom filter false positive rates

---

## Bolt Suggestions

| Bolt | Type | Stories | Objective |
|------|------|---------|-----------|
| 009-policy-revocation | DDD | 001, 003, 005 | File-based sources + revocation cache |
| 010-policy-revocation | DDD | 002, 004 | gRPC streaming sources |

---

## Notes

- File mode is explicitly a temporary mechanism for development/testing while Mini Authority (intent 005) is not yet complete
- The revocation cache (story 005) is shared between file and gRPC modes — build it first
- gRPC stories depend on firma-proto being stable (intent 003 is complete)
