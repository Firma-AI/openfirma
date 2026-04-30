# openauthority-authority — Mini Authority

> **NOT FOR PRODUCTION USE.**
> This is the Mini Authority (OpenAuthority OSS v1) — a local development and testing
> service only. It has no HA, no audit log, no HSM, and no access controls on
> the management interface. Run it on localhost or in an isolated dev/CI
> environment.

The Mini Authority is the pre-flight gate for the OpenAuthority enforcement stack. It
evaluates Cedar policies and issues signed PASETO v4 capability tokens that the
Sidecar validates on every outbound agent call. It also streams policy bundle
updates and revocation events to connected Sidecars.

```
agent ──IssueCapability──▶ Authority ──▶ Cedar eval ──▶ signed token
                                │
                   WatchPolicyBundle / WatchRevocations
                                │
Sidecar ◀───────────────────────┘   (hot-reload; never on the hot path)
```

Authority is contacted **once per session** (pre-flight). The Sidecar enforces
on every call, fully locally, with no network round-trips.

---

## Quick start

### 1. Build

```bash
cargo build -p openauthority-authority
```

Or pull the Docker image (see [Docker](#docker)).

### 2. Generate a signing key

```bash
openauthority-authority generate-key --output openauthority-authority.key
# Writes openauthority-authority.key (secret, 0600) and openauthority-authority.pub
```

The public key (`openauthority-authority.pub`) must be distributed to every Sidecar
instance so it can verify tokens.

### 3. Create a config file

```toml
# authority.toml
listen_addr        = "[::1]:50051"
policy_dir         = "examples/policies"   # must contain schema.cedarschema + *.cedar files
revocation_file    = "revocations.txt"
key_file           = "openauthority-authority.key"
max_ttl_seconds    = 3600
bundle_ttl_seconds = 30
log_level          = "info"
```

`policy_dir` must contain at least one `*.cedar` policy file. The schema is embedded in the
binary — no `schema.cedarschema` is required unless you want to override it (place one in
`policy_dir` or set `schema_path` in the config). Example policies are in `examples/policies/`.

All other fields are optional — defaults are shown above.

### 4. Start the server

```bash
openauthority-authority --config authority.toml
```

Expected startup output (JSON lines):

```
{"level":"INFO","listen_addr":"[::1]:50051","policy_dir":"...","message":"openauthority-authority starting"}
{"level":"WARN","message":"NOT FOR PRODUCTION USE: ..."}
{"level":"INFO","version":"a3f1...","policy_count":3,"message":"cedar policies loaded"}
{"level":"INFO","port":50051,"message":"gRPC server listening"}
```

---

## Configuration reference

| Key | Default | Description |
|-----|---------|-------------|
| `listen_addr` | `[::1]:50051` | gRPC bind address |
| `policy_dir` | `policies` | Directory scanned for `*.cedar` files |
| `revocation_file` | `revocations.txt` | One token ID per line; created on first revoke |
| `key_file` | `openauthority-authority.key` | 64-byte Ed25519 secret key (seed \|\| public) |
| `max_ttl_seconds` | `3600` | Token TTL is clamped to this value |
| `bundle_ttl_seconds` | `30` | TTL advertised in `PolicyBundleUpdate` messages |
| `log_level` | `info` | `tracing` filter — e.g. `debug`, `info`, `warn` |

All keys can be overridden with environment variables using the
`FIRMA_AUTHORITY_` prefix (e.g. `FIRMA_AUTHORITY_LISTEN_ADDR`). Environment
variables take precedence over the TOML file.

---

## Policy files

The Authority loads every `*.cedar` file found in `policy_dir` at startup and
hot-reloads them when the directory changes. The `schema.cedarschema` file in
the same directory defines the entity types and the 15 canonical OpenAuthority actions
(FEP v0.1 §2.3.5).

### Entity UID conventions

| Role | Format |
|------|--------|
| Principal | `OpenAuthority::Agent::"<agent_id>"` |
| Action | `OpenAuthority::Action::"<action_class>"` |
| Resource | `OpenAuthority::Resource::"<resource_uri>"` |

### Context fields (populated by the Sidecar at enforcement time)

| Field | Type | Description |
|-------|------|-------------|
| `session_id` | String | Enclosing session identity |
| `timestamp_ms` | Long | Unix epoch ms at evaluation time |
| `params` | String | JSON-serialised `intent.params` |
| `risk_score` | Long | Static or pre-computed risk attribute (v1 = 0) |
| `budget_remaining` | Long | Ceiling minus consumed; `i64::MAX` when unbounded |
| `session_duration_s` | Long | Seconds since token issuance |
| `action_count` | Long | Monotonic per-session call counter (1-based) |

### Example policies

Three copy-paste-ready examples ship in `policies/`:

| File | Actions covered |
|------|-----------------|
| `payment.cedar` | `payment.purchase`, `payment.transfer` |
| `communication.cedar` | `communication.internal.send`, `communication.external.send` |
| `filesystem.cedar` | `filesystem.read`, `filesystem.write`, `filesystem.delete` |

Each file follows the same pattern: permit rules with `when {}` guards for
acceptable conditions, and a global `forbid` for hard-blocked states. Cedar
evaluation is default-deny — no permit means no access.

---

## gRPC services

The Authority implements `openauthority.v1.AuthorityService` (see
`crates/openauthority-proto/proto/openauthority/v1/authority.proto`).

### `IssueCapability` (unary)

Evaluates Cedar policies and issues a signed PASETO v4 token.

```
→ IssueCapabilityRequest { agent_id, session_id, requested_actions[], resource_scope, requested_ttl_seconds }
← IssueCapabilityResponse { granted, token, deny_reason, deny_message }
```

The issued token contains: `token_id`, `agent_id`, `session_id`, `action_set`,
`resource_scope`, `issued_at`, `expiry`, `context_hash` (SHA-256 binding the
token to the policy bundle version).

### `WatchPolicyBundle` (server streaming)

Streams `PolicyBundleUpdate` messages. The Authority pushes the current bundle
immediately on connect, then pushes again whenever the policy directory changes.
Sidecars use this to stay in sync without polling.

```
→ WatchPolicyBundleRequest { current_version }
← stream of PolicyBundleUpdate { bundle, updated_at }
```

### `WatchRevocations` (server streaming)

Replays historical revocation events since a given timestamp, then streams new
events as they occur.

```
→ WatchRevocationsRequest { since }
← stream of RevocationEvent { token_id, reason, timestamp }
```

---

## Connecting a Sidecar

Point the Sidecar at the Authority address in its config:

```toml
[authority]
address = "http://[::1]:50051"
public_key_file = "openauthority-authority.pub"
```

The Sidecar will call `IssueCapability` at session start, subscribe to
`WatchPolicyBundle` and `WatchRevocations` for continuous updates, then enforce
every outbound call locally with no further Authority contact.

---

## Revoking a token

```bash
openauthority-authority --config authority.toml revocations add <token-id> --reason "session-terminated"
```

The Sidecar receives the revocation event within one streaming heartbeat and
denies subsequent calls carrying the revoked token.

To remove expired entries from the revocation file:

```bash
openauthority-authority --config authority.toml revocations compact
```

---

## End-to-end flow

```
1. Agent starts → calls IssueCapability(agent_id, session_id, actions, resource)
2. Authority evaluates Cedar policy
   - DENY → IssueCapabilityResponse { granted: false, deny_reason }
   - ALLOW → signs PASETO v4 token, returns IssueCapabilityResponse { granted: true, token }
3. Agent holds token; attaches it to each outbound request header
4. Sidecar intercepts the request (Stage 1: parse + verify token, check expiry + revocation)
5. Sidecar runs Stage 2: Cedar eval with live policy bundle + context
   - DENY  → 403 returned to agent
   - ALLOW → request forwarded to destination
```

See `example_agents/` for runnable Python (OpenAI SDK) and TypeScript (Google
ADK) agents that exercise this full flow.

---

## Docker

```bash
docker build -f crates/openauthority-authority/Dockerfile -t openauthority-authority .

docker run --rm \
  -p 50051:50051 \
  -v /path/to/policies:/app/policies:ro \
  -v /path/to/data:/app/data \
  -e OPENAUTHORITY_KEY_FILE=/app/data/openauthority-authority.key \
  openauthority-authority
```

The image copies the bundled `policies/` directory into `/app/policies`. Mount
your own policy directory over it to use custom policies.
