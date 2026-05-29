---
title: Read & verify the audit log
description: Tail the JSON-lines audit stream, decode the envelope, verify the signature, and use the log to debug a DENY.
---

The audit log is the system's ground truth. Every decision the [pipeline](../../concepts/pipeline/) makes — ALLOW or DENY, Stage 1 or Stage 2 — produces an event with the canonical envelope, the matched policy, the validated capability claims, and a signature. This guide shows you how to read it, verify a signature, and use the log to debug a surprise denial.

You should already have a Sidecar running with the `[audit]` block configured ([Run the sidecar standalone](../run-the-sidecar/)).

## Sink choices

The `[sidecar.audit]` block in `firma.toml` selects a sink:

| Sink     | Configuration                                           | Use when                                                                     |
| -------- | ------------------------------------------------------- | ---------------------------------------------------------------------------- |
| `stdout` | `sink = "stdout"`                                       | Local dev; pipe into `jq` or a tail tool.                                    |
| `file`   | `sink = "file"`, `file_path = "..."`                    | Single-host deployments with rotation handled outside.                       |
| `wal`    | `sink = "wal"`, `wal_path = "..."`, `wal_max_bytes = N` | High-throughput; resilient to crashes; consume with a separate tail process. |
| `grpc`   | `sink = "grpc"`, `grpc_url = "..."`                     | Centralized collector ingesting from many Sidecars.                          |

For this guide, assume `sink = "file"` and `file_path = "/tmp/firma-standalone/logs/audit.jsonl"`.

The audit worker signs events off the hot path with the ECDSA P-256 key configured under `signing_key_path`. Signing never blocks the request: the Sidecar acknowledges the decision to the agent, then the worker handles delivery and signing.

## Anatomy of an audit event

A single line of the JSONL log decodes to something like:

```json
{
  "audit_id": "01HX...",
  "timestamp_ms": 1717505648761,
  "envelope": {
    "session_id": "session-001",
    "agent_id":   "support-agent",
    "intent": {
      "action_class": "communication.external.send",
      "resource": {
        "host": "paste.rs",
        "path": "/",
        "provider": null
      },
      "params": "{\"body\":\"...\"}",
      "raw_transport": "https"
    }
  },
  "capability": {
    "token_id":   "79dd9ffb-…",
    "agent_id":   "support-agent",
    "session_id": "session-001",
    "action_set": ["communication.external.send"],
    "resource_scope": "*"
  },
  "decision": {
    "outcome": "DENY",
    "stage":   "constraint_enforcement",
    "reason":  "PolicyDenied",
    "matched_policies": ["forbid_at_support-agent.cedar_15"]
  },
  "connector": null,
  "signature": {
    "algorithm": "ES256",
    "value":     "MEUCIQDh..."
  }
}
```

Field-by-field:

- **`audit_id`** — ULID per event. Sortable by time, unique even across restarts.
- **`envelope`** — the canonical request the pipeline operated on. Immutable across the lifetime of the event.
- **`capability`** — what Stage 1 validated, or `null` for events that failed before Stage 1.
- **`decision`** — the outcome plus a `stage` field telling you which stage decided. For DENYs, `reason` and `matched_policies` say why.
- **`connector`** — populated only for ALLOWs that reached the connector. Includes `credential_injected`, upstream status, dispatch errors.
- **`signature`** — ECDSA P-256 over the canonical bytes of the rest of the event.

## Tail the log

If the Sidecar is running under [`firma sidecar start`](../manage-the-stack/), use `firma monitor` — it knows the state-dir layout and adds filtering by decision, action class, agent, sandbox, and time window:

```bash
firma monitor --state-dir /var/run/firma --source audit --decision deny
```

When several `firma run` invocations share the same audit log, every `ExecutionEvent` carries a `sandbox_id` matching the marker directory under `$XDG_RUNTIME_DIR/firma/run/<sandbox_id>/`. Filter to a single run with:

```bash
firma monitor --sandbox-id abc123def --source audit
```

Pretty output appends `sandbox=<id>` after `agent=` when the field is set; passthrough events and externally started Sidecars leave it empty.

For ad-hoc inspection of a raw `audit.jsonl`:

```bash
tail -f /tmp/firma-standalone/logs/audit.jsonl | jq '.'
```

For just denials:

```bash
tail -f /tmp/firma-standalone/logs/audit.jsonl | \
  jq 'select(.decision.outcome == "DENY")'
```

For specific agents:

```bash
tail -f /tmp/firma-standalone/logs/audit.jsonl | \
  jq 'select(.envelope.agent_id == "support-agent")'
```

## Verify a signature

The audit signature is your tamper-evidence. To verify, you need:

1. The public side of the signing key.
2. The exact canonical bytes that were signed.

Generate the public key from the signing key:

```bash
openssl ec -in /tmp/firma-standalone/audit.key -pubout -out /tmp/firma-standalone/audit.pub
```

Verification of a single line is straightforward in any language with ECDSA P-256 support; the canonical bytes are everything in the event *except* the `signature` field, serialized with sorted keys. A pseudocode verifier:

```python
import json, base64, hashlib
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes, serialization

with open("/tmp/firma-standalone/audit.pub", "rb") as f:
    pub = serialization.load_pem_public_key(f.read())

with open("/tmp/firma-standalone/logs/audit.jsonl") as f:
    for line in f:
        event = json.loads(line)
        sig_b64 = event.pop("signature")["value"]
        # canonical: sort keys, no whitespace
        canonical = json.dumps(event, separators=(",", ":"), sort_keys=True)
        sig = base64.b64decode(sig_b64)
        try:
            pub.verify(sig, canonical.encode(), ec.ECDSA(hashes.SHA256()))
            print(f"OK  {event['audit_id']}")
        except Exception:
            print(f"BAD {event['audit_id']}")
```

In production, you'd run this against your archived audit log on a regular cadence — daily, weekly, or per-incident — and alert on any mismatch.

## Debugging a surprise DENY

The audit log is the first place to look when an agent reports an unexpected failure. The `decision.stage` and `decision.reason` fields tell you where to look next.

### Stage 0: `MappingNotFound`

The normalizer found no rule for `(method, host, path)`. Either:

- Add a rule to your mapping ([Extend the action-class mapping](../extend-mapping/)).
- Or accept that this destination shouldn't be reachable at all, and figure out why the agent tried.

### Stage 1: `CapabilityNotFound`

The Sidecar has no capability matching `(session_id, action_class, resource)` for this request. Check:

- Is a capability seed for this agent loaded? Look at the Sidecar's startup log for `seeded N capability`.
- Does the capability's `action_set` include the request's `action_class`?
- Does the capability's `resource_scope` match the request's host+path?

### Stage 1: `CapabilityExpired`

The token is past its `expiry`. Issue a fresh one. If this happens "right after" issuance, you have clock drift between Authority and Sidecar — bump `[capability_validation].clock_skew_tolerance_seconds`.

### Stage 1: `CapabilityRevoked`

Someone revoked the `token_id` (intentional or accidental). Cross-check the Authority's `revocations.txt`.

### Stage 2: `PolicyDenied`

Cedar evaluated and denied. The `matched_policies` field tells you which rule fired. Open the Cedar file at the indicated location and read the rule.

If you expected a *permit* to fire and a *forbid* fired instead, remember: `forbid` always wins. The fix is usually narrowing the forbid, not adding a permit.

### Stage 2: `PolicyBundleStale`

The bundle is older than `bundle_ttl_seconds`. Either the Authority is unreachable, or the bundle TTL is too tight. Check the Sidecar's connection log to the Authority and the configured TTL.

### Connector: `Timeout` or `NetworkError`

The decision was ALLOW; the connector tried to dispatch and failed. The audit event is `decision.outcome = "ALLOW"` with a `connector.error` field set. The agent saw a 502 — but from the policy's perspective, the call was permitted. This split is intentional; see [Connectors](../../concepts/connectors/).

## Scope: events the audit log does not capture (V0.1)

The audit log and `firma monitor` cover the **network / L7 layer only**. Every ALLOW and DENY the enforcement pipeline makes — Stage 1 and Stage 2 — plus the fail-closed rejections the proxy raises before the pipeline runs (malformed request, strict-MITM preflight failure) produce an audit event you can see in monitor. Network-layer denials carry the validated `agent_id` and `token_id` when a capability was checked, so `firma monitor --agent <id>` keeps them.

**Below-network denials are not surfaced in V0.1.** When an agent runs under `firma run`, the process sandbox enforces two boundaries the audit log does not observe:

- **seccomp syscall denials** — blocked syscalls during `run_shell`. The filter returns `EPERM` to the sandboxed process (`SECCOMP_RET_ERRNO`); the kernel does not notify the parent, so `firma run` never sees the denial.
- **filesystem write denials** — writes outside the agent's allowlisted paths. The sandbox enforces these with read-only bind mounts; the sandboxed process gets `EROFS`, again with no parent-observable signal.

This is a **documented limitation, not a silent omission**. There is no feedback channel from the process sandbox into the Sidecar's audit pipe in V0.1, and the Sidecar is the sole producer of audit events. Surfacing seccomp and filesystem denials would require switching seccomp to `SECCOMP_RET_USER_NOTIF` (or an equivalent notification path) plus an IPC channel from `firma run` into the audit pipeline — deferred post-V1. See ADR-56 for the process-level enforcement scope boundary.

To confirm a below-network block in V0.1, observe it from the agent side instead: the blocked syscall surfaces as `EPERM` and the blocked write as `EROFS` in the agent's own output.

## Building a useful workflow

A small stack that catches most operational issues:

1. **Live tail** during development: `tail -f .../audit.jsonl | jq 'select(.decision.outcome == "DENY")'`. Surfaces unexpected denials in real time.
2. **Daily roll-up** in production: a cron job that summarizes counts by `decision.reason`, agent, and host. Alerts on outliers.
3. **Signature verification** scheduled separately: confirms no tampering in the durable copy.
4. **Indexed search** for incident response: ship the JSONL to a search backend (OpenSearch, Splunk, etc.) keyed on `audit_id`, `agent_id`, `session_id`, and `decision.reason`.

The audit log's value compounds with how easily you can search it. A grep-friendly format, durable storage, and signature verification are the three things to invest in first.

## Common gotchas

**`audit.jsonl` is empty after a request.** The audit worker writes asynchronously; events flush every few hundred milliseconds. If the file is *never* written, the Sidecar probably crashed at startup with a permissions error on `signing_key_path` — check stderr. Note that a per-run sidecar autostarted by `firma run` defaults its audit sink to a file at `<state_dir>/audit.jsonl` (the path `firma monitor` tails) even when the template configures no sink, so a `firma run` decision is monitorable out of the box; an explicit `[sidecar.audit]` sink in your template still wins.

**Signature verification fails for events you didn't tamper with.** Almost always a JSON canonicalization mismatch. The signed bytes are RFC 8785 (JCS) — sorted keys, no whitespace, no trailing newline. Any reformatting of the file (a pretty-printer, a text editor) breaks verification.

**`decision.matched_policies` is empty for an ALLOW.** Means no `permit` rule matched and the request fell through Cedar's default-deny... wait, that should be a DENY. If you see this, it's almost certainly a logging bug — file an issue with the event id.

**Audit log shows `decision.outcome = "ALLOW"` but the agent says the call failed.** Check `connector` — most likely the upstream rejected it (network, timeout, 5xx). The Sidecar allowed it; the world rejected it.

## What's next

- [Concepts: The enforcement pipeline](../../concepts/pipeline/) — the design behind the stages and reasons.
- [Concepts: Connectors](../../concepts/connectors/) — what `connector.error` means.
- [Concepts: Threat model](../../concepts/threat-model/) — how the audit log fits into the security story.
