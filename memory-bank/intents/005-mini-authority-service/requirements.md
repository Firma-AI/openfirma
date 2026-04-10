---
intent: 005-mini-authority-service
phase: inception
status: draft
created: 2026-04-01T10:00:00Z
updated: 2026-04-01T10:00:00Z
---

# Requirements: Mini Authority Service

## Intent Overview

Implement the real `firma-authority` binary — the control-plane component that evaluates Cedar policies at issuance time, signs capability tokens via PASETO v4, and distributes policy bundles and revocation events to Sidecars over gRPC streaming. The authority loads Cedar policies from `.cedar` files on disk, supports hot-reload via filesystem watching, and exposes the three `AuthorityService` RPCs defined in `firma.v1.authority` proto.

## Business Goals

| Goal | Success Metric | Priority |
|------|----------------|----------|
| Agents can request and receive scoped capability tokens | IssueCapability RPC returns signed PASETO v4 tokens that pass `PasetoV4Verifier` round-trip | Must |
| Cedar policies gate token issuance | Requests violating loaded policies are denied with reason codes | Must |
| Sidecars receive policy bundles over streaming | WatchPolicyBundle streams current bundle on connect + pushes on change | Must |
| Sidecars receive revocation events over streaming | WatchRevocations streams events after a given timestamp | Must |
| Policy files can be updated without restart | File watcher detects `.cedar` file changes and reloads policies | Must |
| Authority is operationally simple | Single binary, file-based config, zero external infrastructure | Should |

---

## Functional Requirements

### FR-1: Cedar Policy Loading
- **Description**: On startup, load all `.cedar` policy files and the entity schema from a configurable directory. Parse and validate them into a Cedar `PolicySet` and `Schema`.
- **Acceptance Criteria**: Authority starts successfully with valid `.cedar` files; fails fast with clear error on invalid policy syntax or schema mismatch.
- **Priority**: Must
- **Related Stories**: TBD

### FR-2: Cedar Policy Hot-Reload
- **Description**: Watch the policy directory for file changes (create, modify, delete). On change, re-parse the full policy set. If valid, atomically swap the active policy set. If invalid, log an error and keep the previous valid set.
- **Acceptance Criteria**: Modifying a `.cedar` file on disk causes the next `IssueCapability` call to use the updated policy; invalid edits do not crash the authority or leave it in a broken state.
- **Priority**: Must
- **Related Stories**: TBD

### FR-3: IssueCapability RPC
- **Description**: Implement the `IssueCapability` unary RPC. Build a Cedar evaluation context from the request (agent_id, requested_actions, resource_scope, session_id), evaluate against the loaded policy set. On allow: generate `CapabilityClaims`, sign with `PasetoV4Signer`, return the signed token. On deny: return `granted=false` with deny_reason and deny_message.
- **Acceptance Criteria**: (1) Valid request matching policy returns `granted=true` + valid PASETO v4 token; (2) Request violating policy returns `granted=false` + reason code; (3) Token contains correct agent_id, session_id, actions, resources, expiry, context_hash.
- **Priority**: Must
- **Related Stories**: TBD

### FR-4: Token TTL and Expiry
- **Description**: Honour `requested_ttl_seconds` from the issuance request, clamped to a configurable maximum (default 3600s). Set `issued_at` to now and `expires_at` to `issued_at + TTL`.
- **Acceptance Criteria**: Token `expires_at` matches `issued_at + min(requested_ttl, max_ttl)`; default max TTL is 3600s and is overridable via config.
- **Priority**: Must
- **Related Stories**: TBD

### FR-5: WatchPolicyBundle Streaming
- **Description**: Implement server-streaming RPC. On connect, immediately send the current policy bundle (serialized Cedar policies + version hash). When hot-reload swaps the policy set, push an update to all connected streams. If client sends `current_version` matching the server's version, skip the initial push.
- **Acceptance Criteria**: (1) New client receives current bundle immediately; (2) Policy file change triggers push to all connected clients; (3) Bundle includes version string and TTL; (4) Client with matching version does not receive redundant push.
- **Priority**: Must
- **Related Stories**: TBD

### FR-6: WatchRevocations Streaming
- **Description**: Implement server-streaming RPC. Maintain an in-memory revocation log. On connect, replay events after the client's `since` timestamp. Push new revocation events as they occur.
- **Acceptance Criteria**: (1) Client with `since` in the past receives all events after that timestamp; (2) New revocation events are pushed to all connected clients; (3) Events include token_id, reason, and timestamp.
- **Priority**: Must
- **Related Stories**: TBD

### FR-7: Revocation via File/CLI
- **Description**: Support revoking tokens by writing token IDs to a revocation file (one per line) or via a CLI subcommand (`firma-authority revoke <token_id>`). The authority watches the revocation file and emits events on the WatchRevocations stream.
- **Acceptance Criteria**: (1) Adding a token_id to the revocation file triggers a `RevocationEvent`; (2) CLI `revoke` subcommand adds to the revocation file and triggers the event; (3) Duplicate revocations are idempotent.
- **Priority**: Must
- **Related Stories**: TBD

### FR-8: Configuration
- **Description**: Accept configuration via TOML file and/or environment variables. Key settings: listen address (default `:50051`), policy directory path, revocation file path, max token TTL, Ed25519 key path, log level.
- **Acceptance Criteria**: Authority starts with default config; all settings overridable via TOML or env vars; missing key file fails fast with clear error.
- **Priority**: Must
- **Related Stories**: TBD

### FR-9: Ed25519 Key Management
- **Description**: Load Ed25519 signing key from a file path (PEM or raw bytes). Use for PASETO v4 token signing via existing `PasetoV4Signer`. Optionally generate a key pair on first run if no key exists (dev mode convenience).
- **Acceptance Criteria**: (1) Authority loads existing key and signs tokens; (2) Missing key with `--generate-key` flag creates a new key pair; (3) Missing key without flag fails fast.
- **Priority**: Must
- **Related Stories**: TBD

### FR-10: Structured Logging and Health
- **Description**: Use `tracing` with structured JSON output. Log policy load/reload events, issuance decisions (allow/deny with context), revocation events, and stream connect/disconnect. Expose a gRPC health check or simple HTTP `/healthz` endpoint.
- **Acceptance Criteria**: (1) All key operations produce structured log lines; (2) Health endpoint returns 200 when authority is ready (policies loaded, key available).
- **Priority**: Should
- **Related Stories**: TBD

---

## Non-Functional Requirements

### Performance
| Requirement | Metric | Target |
|-------------|--------|--------|
| IssueCapability latency | p95 latency | < 5ms (policy eval + sign) |
| Policy reload | Time to swap | < 100ms for typical policy set |
| Stream fan-out | Connected sidecars | Support 100+ concurrent watchers |

### Scalability
| Requirement | Metric | Target |
|-------------|--------|--------|
| Concurrent issuance | Requests/second | > 1000 |
| Policy set size | Number of Cedar policies | Up to 500 policies |
| Revocation log | In-memory events | Up to 100,000 entries |

### Security
| Requirement | Standard | Notes |
|-------------|----------|-------|
| Token signing | PASETO v4 (Ed25519) | Reuse `PasetoV4Signer` from firma-core |
| Key storage | File-based, 0600 permissions | Key never exposed over network |
| Policy validation | Cedar schema enforcement | Reject malformed policies at load time |
| No plaintext secrets | - | Keys loaded from file, not env vars or CLI args |

### Reliability
| Requirement | Metric | Target |
|-------------|--------|--------|
| Invalid policy resilience | Behavior | Keep last-known-good on bad reload |
| Stream reconnection | Behavior | Clients can reconnect with `since`/`current_version` |
| Graceful shutdown | Drain time | < 5s to drain active streams |

### Compliance
| Requirement | Standard | Notes |
|-------------|----------|-------|
| Zero infrastructure | V1 principle | No database, no external services |
| Audit trail | Structured logs | All issuance/revocation decisions logged |

---

## Constraints

### Technical Constraints

**Project-wide standards**: Required standards will be loaded from memory-bank standards folder by Construction Agent.

**Intent-specific constraints**:
- Must implement the `AuthorityService` proto exactly as defined in `firma.v1.authority` — no proto changes
- Must use `PasetoV4Signer` from `firma-core` for token signing — no new crypto
- Must use `cedar-policy` crate for policy evaluation — first Cedar dependency in the workspace
- `PolicyBundle` struct in `firma-core/traits.rs` currently has an opaque `_private` field — will need to be fleshed out to hold real Cedar policy data
- `firma-authority` crate already exists as a binary stub with tokio + tracing

### Business Constraints
- V1: zero external infrastructure (no database, no Redis, no message queue)
- Must work standalone for local development (intent 007 will orchestrate)

---

## Assumptions

| Assumption | Risk if Invalid | Mitigation |
|------------|-----------------|------------|
| Intent 004 example agents and Cedar base schema will be available before shipping | Cannot validate end-to-end | Build with own test Cedar policies; plug intent 004 artifacts later |
| Cedar policy files are small enough to hold in memory | Memory pressure with large policy sets | Document policy size limits; add metrics |
| Single signing key is sufficient for V1 | No key rotation story | Design key loading to support future rotation |
| File-based revocation is sufficient for V1 | Not suitable for production multi-instance | Document as V1 limitation; future: gRPC revoke endpoint |
| `PolicyEvaluator` trait in firma-core may need async or richer context | Trait signature mismatch | May need to extend trait or add authority-specific evaluator |

---

## Open Questions

| Question | Owner | Due Date | Resolution |
|----------|-------|----------|------------|
| Should `PolicyBundle` in firma-core be refactored to hold real Cedar data, or should authority use its own internal type? | Construction | During bolt planning | Pending |
| Should the context_hash in CapabilityClaims hash the full Cedar policy set or just the entity context? | Construction | During domain model | Pending |
| What Cedar entity types and action types should the authority define for its own schema? | Intent 004 team | Before integration | Assume base schema from intent 004; define minimal own schema if needed |
