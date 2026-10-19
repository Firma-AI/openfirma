---
title: Read & verify the audit log
description: Tail the JSON-lines audit stream, read flat execution events, verify signatures, and use the log to debug a DENY.
---

The audit log is the system's ground truth. Every decision the [pipeline](../../concepts/pipeline/) makes — ALLOW or DENY — produces a flat execution event with the normalized action/resource, decision metadata, connector dispatch fields, and a signature. This guide shows you how to read it, verify a signature, and use the log to debug a surprise denial.

You should already have a Sidecar running with the `[sidecar.audit]` block configured ([Run the sidecar standalone](../run-the-sidecar/)).

## Sink choices

The `[sidecar.audit]` block in `firma.toml` selects a sink:

| Sink     | Configuration                                                                          | Use when                                                                      |
| -------- | -------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| `stdout` | `sink = "stdout"`                                                                      | Local dev or production on Cloud Run; pipe into `jq` or ship structured JSON. |
| `file`   | `sink = "file"`, `file_path = "..."`                                                   | Single-host deployments with rotation handled outside.                        |
| `grpc`   | `sink = "grpc"`, `grpc_url = "..."`, `buffer_path = "..."`, `buffer_max_size = "100 MiB"` | Centralized collector ingesting from many Sidecars.                           |
| `wal`    | `sink = "wal"`, `grpc_url = "..."`, `wal_path = "..."`, `wal_max_size = "100 MiB"` | Journal before delivery; retain events until acknowledged or archived as rejected. |

The `grpc` sink buffers events while the collector is unreachable and replays them
on reconnect. Past `buffer_max_size`, the oldest buffered events are evicted.
Events sent over a live stream are not journaled and can be lost if that stream
breaks before the collector stores them. Use `wal` when each event must remain
pending until a matching durable acknowledgement arrives.

Buffered events are cleared only once the collector acknowledges them, and the buffer outlives the process, so a replay that fails partway and a Sidecar restart both leave the events intact for the next attempt.

Both network sinks attach configured sidecar credentials. They use separate file
formats and delivery contracts; do not share a buffer path with a WAL journal.
Buffered `grpc` rejects records carrying run evidence, including empty evidence,
before sending them to a legacy collector. An existing buffer containing such a
record is retained and startup fails; it must not be silently downgraded to an
unknown actor. Use `wal` for evidence-aware delivery.

For this guide, assume `sink = "file"` and `file_path = "/tmp/firma-standalone/logs/audit.jsonl"`.

The audit worker signs events off the hot path with the ECDSA P-256 key configured under `signing_key_path`. Signing never blocks the request: the Sidecar acknowledges the decision to the agent, then the worker handles delivery and signing.

## Durable delivery

Use `wal` when delivery must survive a collector outage or worker restart:

```toml
[sidecar.audit]
sink = "wal"
grpc_url = "https://collector.example.com"
wal_path = "/var/lib/firma/audit.jsonl"
wal_max_size = "100 MiB"
signing_key_path = "/etc/firma/audit.pem"
```

Create the parent directory first and keep it private. On Unix, the sink creates
queue, scope, lock, and rejection files with mode `0600`; on Windows, restrict
access using the directory ACL. Only one writer may use a WAL path at a time.

Each event is appended and synced before the evidence-aware `SubmitEvent` RPC.
Only a receipt confirming durable persistence of that exact event permits removal.
A successful send to a local channel or an HTTP/gRPC connection is not that receipt.
Lost responses cause replay; the collector must deduplicate by its authenticated
workspace, sidecar, and source event ID. The legacy `StreamEvents` method is not a
fallback: an old server could silently discard newer attribution evidence.
Upgrade collectors before workers. An unsupported collector leaves WAL records
pending. The buffered `grpc` sink continues using the legacy streaming contract;
it does not provide the WAL's per-event durable acknowledgement guarantee.

`wal_request_timeout` (default `5s`) bounds each delivery attempt, from connecting
through the collector's durable commit. Keep it above the collector's commit
latency, or a slower collector receives the same record on every retry while the
journal fills. Keep it well below your supervisor's termination grace period,
because shutdown waits for the attempt in progress. The buffered `grpc` sink's
equivalent is `replay_ack_timeout` (default `30s`), the wait for a replay
acknowledgement. The [configuration reference](https://github.com/Firma-AI/openfirma/blob/main/docs/configuration.md#sidecaraudit)
covers both trade-offs.

`run_evidence`, when present, is retained with its original event through reconnects.
It is opaque, not a human identity, and not authenticated by the legacy event
signature. No current producer issues it. Collectors must explicitly reject
unsupported or invalid evidence rather than store an unknown actor in its place.

The sibling `audit.jsonl.scope` pins the endpoint and workspace/sidecar identity,
not the PSK or current user. PSK rotation is permitted; using the queue for another
workspace or sidecar is refused. Keep the scope and queue together during recovery.
A nonempty older WAL without a scope file is left intact and refused. Archive it
for explicit migration after establishing its original destination; use a new WAL
path for new traffic. Do not fabricate a scope from the current login.

A permanent `INVALID_ARGUMENT` response moves that one record to
`audit.jsonl.rejected.jsonl`, including its exact original bytes and rejection
reason. The archive is synced before queue removal, allowing later runs to proceed.
Malformed local records are archived the same way. The archive's `record` field
is a JSON byte array, so even non-UTF-8 fragments survive. Interrupted tail writes
are separated before appending again; an incomplete archive line remains available
for inspection. Archive-write failure stops the sink without reclaiming records.
Inspect and retain rejection archives according to your retention policy; they
can contain sensitive evidence and are never pruned automatically.

`wal_max_size` bounds pending bytes, not rejected archives. At capacity, the sink
fails explicitly and retains pending records instead of evicting the oldest ones.
The Sidecar reports a terminal sink failure and shuts down with a failure status,
including while waiting for Authority readiness. Free capacity or correct the
reported storage error before restarting. Readiness is not a delivery check.
This guarantee starts at successful journal sync: the asynchronous producer
channel is not durable, and this sink does not promise capture of events lost
before sync or after sink failure. Reconnect attempts continue once a second even
without new traffic. Shutdown retains unacknowledged records; a stopped sink may
need to restart to finish a backlog.

## Anatomy of an audit event

A single line of the JSONL log decodes to something like:

```json
{
  "event_id": "aevt_01j0000000e008000000000001",
  "session_id": "session-001",
  "token_id": "ctok_01j0000000e008000000000001",
  "agent_id": "agt_01j0000000e008000000000001",
  "action": "communication.external.send",
  "resource": "paste.rs/",
  "decision": 2,
  "deny_reason": "policy denied: policy denied action 'communication.external.send' on resource 'paste.rs/'",
  "enforcement_latency_us": 420,
  "context_hash": "sha256:abc123",
  "bundle_version": "local",
  "timestamp": 1717505648761000000,
  "dispatch_status": 0,
  "dispatch_latency_us": 0,
  "response_size": 0,
  "sandbox_id": "",
  "provenance": "a1b2c3...",
  "thread_id": "d4e5f6...",
  "parent_action_id": "7a8b9c...",
  "signature": "MEUCIQ=="
}
```

Field-by-field:

- **`event_id`** — `aevt` `TypeID` backed by UUIDv7. Sortable by time, unique even across restarts.
- **`session_id`, `token_id`, `agent_id`** — the session, capability token, and agent identity evaluated by the pipeline.
- **`action`, `resource`** — the normalized action class and opaque resource UID (`host + path`, for example `paste.rs/`).
- **`decision`** — numeric outcome (`1` = ALLOW, `2` = DENY). For DENYs, `deny_reason` is a lowercase string (often `"{reason}: {detail}"`, e.g. `"policy denied: …"`). The troubleshooting headings below use PascalCase labels for readability.
- **`dispatch_status`, `dispatch_latency_us`, `response_size`** — connector result fields. They are zero when the call never dispatched.
- **`sandbox_id`** — set for `firma run` sidecars; empty for externally started Sidecars.
- **`provenance`** — tamper-evident chain anchor (AARM R2 G2): `hex(SHA256(prev || context_hash || action || resource))`. Empty for pre-dispatch outcomes (Deny/StepUp/Defer/Abort).
- **`thread_id`** — server-derived conversation thread identity (AARM R2 G2). Groups admitted actions within a session into a causal thread. Empty for pre-dispatch outcomes.
- **`parent_action_id`** — provenance anchor of the prior admitted action in this thread (AARM R2 G2). Empty for the first admitted action or pre-dispatch outcomes.
- **`signature`** — DER-encoded ECDSA P-256 signature, serialized as a standard (padded) base64 string. The compact opaque value round-trips through structured JSON log pipelines (such as Cloud Logging) without byte loss, so `sink = "stdout"` is reliable for production on Cloud Run.

The optional `run_evidence` extension retains opaque bytes for a future run
attribution protocol. Current producers leave it absent. Its presence does not
authenticate a human actor, and the legacy ECDSA signature does not cover it.
Collectors without a supported verifier reject supplied evidence, including an
empty value, rather than treating it as unknown attribution.

The shared gRPC contract adds `SubmitEvent` and a `durably_persisted` receipt
marker. Evidence-aware clients must not fall back to `StreamEvents` on an older
collector: that server could discard fields it does not understand. The WAL sink
uses this contract. Buffered `grpc` retains legacy streaming and rejects supplied
evidence instead of passing it to a collector that might silently discard it.

## Deserialize records in Rust

The `firma-audit-schema` crate provides the same `ExecutionEvent` and numeric
`Decision` types the Sidecar uses for serialization. It contains no signing,
verification, storage, or transport behavior, so integrations do not need to
depend on `firma-sidecar`.

For a source dependency, add:

```toml
[dependencies]
firma-audit-schema = { git = "https://github.com/Firma-AI/openfirma" }
serde_json = "1"
```

Then deserialize each JSONL record directly:

```rust
use std::fs::File;
use std::io::{BufRead as _, BufReader};

use firma_audit_schema::ExecutionEvent;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let reader = BufReader::new(File::open("audit.jsonl")?);
    for line in reader.lines() {
        let event: ExecutionEvent = serde_json::from_str(&line?)?;
        println!("{:?} {} {}", event.decision, event.action, event.resource);
    }
    Ok(())
}
```

The schema is strict about required fields, known decision codes, and base64
signature encoding. Use a smaller local Serde projection when consuming
partially written records or when unknown future decision codes must remain
visible instead of failing deserialization.

## Tail the log

If the Sidecar is running under [`firma sidecar start`](../manage-the-stack/), use `firma monitor` — it knows the state-dir layout and adds filtering by decision, action class, agent, sandbox, and time window:

```bash
firma monitor --state-dir /var/run/firma --source audit --decision deny
```

When several `firma run` invocations share the same audit log, every `ExecutionEvent` carries the sandbox ID shown by `firma sidecar status`. Filter to a single run with:

```bash
firma monitor --sandbox-id sbx_01j0000000e008000000000001 --source audit
```

Pretty output appends `sandbox=<id>` after `agent=` when the field is set; passthrough events and externally started Sidecars leave it empty.

For ad-hoc inspection of a raw `audit.jsonl`:

```bash
tail -f /tmp/firma-standalone/logs/audit.jsonl | jq '.'
```

For just denials:

```bash
tail -f /tmp/firma-standalone/logs/audit.jsonl | \
  jq 'select(.decision == 2)'
```

For specific agents:

```bash
tail -f /tmp/firma-standalone/logs/audit.jsonl | \
  jq 'select(.agent_id == "support-agent")'
```

## Verify a signature

The audit signature is your tamper-evidence. To verify, you need:

1. The public side of the signing key.
2. The exact canonical bytes that were signed.

Generate the public key from the signing key:

```bash
openssl ec -in /tmp/firma-standalone/audit.key -pubout -out /tmp/firma-standalone/audit.pub
```

Verification of a single line is straightforward in any language with ECDSA P-256 support. The signed payload is the SHA-256 digest of the original execution fields, excluding `signature` and `run_evidence`, concatenated in declaration order with newlines. A pseudocode verifier:

```python
import base64, json, hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization

with open("/tmp/firma-standalone/audit.pub", "rb") as f:
    pub = serialization.load_pem_public_key(f.read())

with open("/tmp/firma-standalone/logs/audit.jsonl") as f:
    for line in f:
        event = json.loads(line)
        sig = base64.b64decode(event["signature"])
        fields = [
            "event_id", "session_id", "token_id", "agent_id", "action",
            "resource", "decision", "deny_reason", "enforcement_latency_us",
            "context_hash", "bundle_version", "timestamp", "dispatch_status",
            "dispatch_latency_us", "response_size", "sandbox_id",
            "provenance", "thread_id", "parent_action_id",
        ]
        def field_value(field):
            if field == "timestamp":
                return str(event.get(field) or 0)
            return str(event.get(field, ""))
        canonical = "\n".join(field_value(field) for field in fields)
        payload = hashlib.sha256(canonical.encode()).digest()
        try:
            pub.verify(sig, payload, ec.ECDSA(hashes.SHA256()))
            print(f"OK  {event['event_id']}")
        except Exception:
            print(f"BAD {event['event_id']}")
```

In production, you'd run this against your archived audit log on a regular cadence — daily, weekly, or per-incident — and alert on any mismatch.

## Debugging a surprise DENY

The audit log is the first place to look when an agent reports an unexpected failure. For DENYs, `deny_reason` tells you where to look next.

### Normalization: `UnclassifiedIntent`

The normalizer found no rule for `(method, host, path)`. Either:

- Add a rule to your mapping ([Extend the action-class mapping](../extend-mapping/)).
- Or accept that this destination shouldn't be reachable at all, and figure out why the agent tried.

### Stage 1: `TokenInvalid`

The Sidecar could not find or verify a capability matching `(session_id, action, resource)` for this request. Check:

- Is a capability seed for this agent loaded? Look at the Sidecar's startup log for `seeded N capability`.
- Does the capability's `action_set` include the request's `action`?
- Does the capability's `resource_scope` match the request's host+path?

### Stage 1: `TokenExpired`

The token is past its `expiry`. Issue a fresh one.

### Stage 1: `TokenRevoked`

Someone revoked the `token_id` (intentional or accidental). Cross-check the Authority's `revocations.txt`.

### Stage 1: `ScopeViolation`

The token is valid, but its action or resource scope does not cover this request. Re-issue with the narrowest scope that covers the intended host+path.

### Stage 2: `PolicyDenied`

Cedar evaluated and denied. Re-run the same case with `firma policy test` against the relevant bundle to see which rule shape is responsible.

If you expected a _permit_ to fire and a _forbid_ fired instead, remember: `forbid` always wins. The fix is usually narrowing the forbid, not adding a permit.

### Stage 2: `PolicyBundleStale`

The Authority-advertised bundle TTL expired without a refresh. Check the Sidecar's connection to the Authority and the Authority's health. The TTL is configured by `[authority].bundle_ttl`; there is no separate Sidecar TTL setting.

### ABORT: `CONNECTOR_TIMEOUT`, `CONNECTOR_FAILURE`, `CONNECTOR_INVALID_REQUEST`, or `CREDENTIAL_INJECTION_FAILED`

The call cleared enforcement, then could not complete. This is not a policy DENY. The Sidecar records `decision = 3`, keeps `dispatch_status = 0` when no upstream response was produced, and sends the agent a gateway-timeout-class response.

For HTTP-facing interceptors the body is:

```json
{
  "aborted": true,
  "reason": "CONNECTOR_FAILURE",
  "detail": "connection refused"
}
```

DENY means the request shape, token, scope, or policy was rejected before execution. ABORT means the request was allowed and then killed or failed locally before completion. The capability token remains active after ABORT. See [Connectors](../../concepts/connectors/) and [Pipeline](../../concepts/pipeline/).

## Scope: events the audit log does not capture (V0.1)

The audit log and `firma monitor` cover the **network / L7 layer only**. Every ALLOW and DENY the enforcement pipeline makes — Stage 1 and Stage 2 — plus the fail-closed rejections the proxy raises before the pipeline runs (malformed request, strict-MITM preflight failure) produce an audit event you can see in monitor. Network-layer denials carry the validated `agent_id` and `token_id` when a capability was checked, so `firma monitor --agent <id>` keeps them.

**Below-network denials are not surfaced in V0.1.** When an agent runs under `firma run`, the process sandbox enforces two boundaries the audit log does not observe:

- **seccomp syscall denials** — blocked syscalls during `run_shell`. The filter returns `EPERM` to the sandboxed process (`SECCOMP_RET_ERRNO`); the kernel does not notify the parent, so `firma run` never sees the denial.
- **filesystem write denials** — writes outside the agent's allowlisted paths. The sandbox enforces these with read-only bind mounts; the sandboxed process gets `EROFS`, again with no parent-observable signal.

This is a **documented limitation, not a silent omission**. There is no feedback channel from the process sandbox into the Sidecar's audit pipe in V0.1, and the Sidecar is the sole producer of audit events. Surfacing seccomp and filesystem denials would require switching seccomp to `SECCOMP_RET_USER_NOTIF` (or an equivalent notification path) plus an IPC channel from `firma run` into the audit pipeline — deferred post-V1. See ADR-56 for the process-level enforcement scope boundary.

To confirm a below-network block in V0.1, observe it from the agent side instead: the blocked syscall surfaces as `EPERM` and the blocked write as `EROFS` in the agent's own output.

## Building a useful workflow

A small stack that catches most operational issues:

1. **Live tail** during development: `tail -f .../audit.jsonl | jq 'select(.decision == 2)'`. Surfaces unexpected denials in real time.
2. **Daily roll-up** in production: a cron job that summarizes counts by `deny_reason`, agent, and resource. Alerts on outliers.
3. **Signature verification** scheduled separately: confirms no tampering in the durable copy.
4. **Indexed search** for incident response: ship the JSONL to a search backend (OpenSearch, Splunk, etc.) keyed on `event_id`, `agent_id`, `session_id`, and `deny_reason`.

The audit log's value compounds with how easily you can search it. A grep-friendly format, durable storage, and signature verification are the three things to invest in first.

## Common gotchas

**`audit.jsonl` is empty after a request.** The audit worker writes asynchronously; events flush every few hundred milliseconds. If the file is _never_ written, the Sidecar probably crashed at startup with a permissions error on `signing_key_path` — check stderr. Note that a per-run sidecar autostarted by `firma run` defaults its audit sink to a file at `<state_dir>/audit.jsonl` (the path `firma monitor` tails) even when the template configures no sink, so a `firma run` decision is monitorable out of the box; an explicit `[sidecar.audit]` sink in your template still wins.

**Signature verification fails for events you didn't tamper with.** Almost always a payload mismatch. The signed bytes are derived from newline-joined fields in declaration order, not from canonical JSON. Reformatting the JSONL does not matter, but changing any field value does.

**You need to know which Cedar rule fired.** The audit event records `deny_reason`, not matched policy IDs. Reproduce the case with `firma policy test` when you need rule-level debugging.

**Audit log shows `decision = 1` but the agent says the call failed.** Check `dispatch_status`, `dispatch_latency_us`, and the Sidecar logs — most likely the upstream rejected it (network, timeout, 5xx). The Sidecar allowed it; the world rejected it.

## What's next

- [Concepts: The enforcement pipeline](../../concepts/pipeline/) — the design behind the stages and reasons.
- [Concepts: Connectors](../../concepts/connectors/) — how dispatch failures are reported.
- [Concepts: Threat model](../../concepts/threat-model/) — how the audit log fits into the security story.
