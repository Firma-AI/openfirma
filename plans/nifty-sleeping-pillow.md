# Generalize the loopback report into a `firma run` audit channel

## Context

Phases 1–5 of the loopback-blocking feature are implemented and committed on
branch `fir-block-loopback-egress` (audit model, Linux seccomp guard, macOS
port-scoping, docs). They introduced a single-purpose control socket:
`firma run`'s egress guard reports one message type —
`BlockedLoopbackReport` — to the Sidecar, which signs it into an audit event.

This refactor generalizes that into a reusable **`firma run` → Sidecar audit
channel**. The loopback block becomes one message variant of a tagged enum, and
the Sidecar's ingest handler becomes generic so future out-of-band producers
(other seccomp blocks, blocked tool launches, command-governance denials) reuse
the same socket, framing, and signing path.

Design decisions (locked):

- **Envelope shape:** `RunAuditMessage { session_id, agent_id, event }` carries
  per-run identity once; `RunAuditEvent` variants stay pure observations.
- **Semantics live in the Sidecar:** `firma-core` holds only wire types. The
  Sidecar handler maps each variant to `(action_class, decision, deny_reason,
  resource)`. `NETWORK_LOOPBACK_ACTION_CLASS` + resource formatting move out of
  `firma-core`. This preserves audit integrity: the reporter states an
  observation; the signer owns the meaning.

Behavior is unchanged end-to-end — same UDS, same newline-delimited JSON, same
signed `network.loopback` DENY in `firma monitor`. This is a rename + reshape,
back-compatible at the socket level, with no second producer added yet.

## Naming

| Old | New |
| --- | --- |
| env `FIRMA_SIDECAR_EGRESS_REPORT_SOCK` | `FIRMA_RUN_AUDIT_SOCK` |
| socket file `egress-report.sock` | `run-audit.sock` |
| `firma-core/src/egress.rs` | `firma-core/src/run_audit.rs` |
| `firma-sidecar/src/egress_report.rs` | `firma-sidecar/src/run_audit_ingest.rs` |
| `BlockedLoopbackReport` | `RunAuditMessage` + `RunAuditEvent::LoopbackBlocked` |
| `build_loopback_audit_payload` | `audit_payload_for(&RunAuditMessage)` |
| `egress_guard::ReportTarget` | `egress_guard::AuditChannel` |
| `report_block` | `report_event` |
| `spawn_egress_report_listener` | `spawn_run_audit_listener` |

## Changes

### 1. `firma-core` — wire types only (`egress.rs` → `run_audit.rs`)

Replace `BlockedLoopbackReport` (and its `resource()` + `NETWORK_LOOPBACK_*`
const) with pure wire types:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunAuditMessage {
    pub session_id: String,
    pub agent_id: String,
    pub event: RunAuditEvent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RunAuditEvent {
    /// Direct connection to a non-sanctioned loopback address, blocked by the
    /// `firma run` egress guard.
    LoopbackBlocked { dst_ip: String, dst_port: u16 },
    // future: SeccompBlocked { syscall: String, detail: String },
    //         ToolLaunchBlocked { tool: String, reason: String },
}
```

- Update `firma-core/src/lib.rs`: module + re-exports (`RunAuditMessage`,
  `RunAuditEvent`); drop `BlockedLoopbackReport` / `NETWORK_LOOPBACK_ACTION_CLASS`.
- Move the IPv4/IPv6 `resource()` round-trip tests to the Sidecar (they now test
  the mapping). Keep a JSON round-trip test for the envelope + variant here.

### 2. `firma-sidecar` — generic ingest (`egress_report.rs` → `run_audit_ingest.rs`)

- Listener (`spawn_listener`, `serve`, `handle_connection`, `ingest_line`)
  unchanged in shape; parse `RunAuditMessage` instead of `BlockedLoopbackReport`.
- Replace `build_loopback_audit_payload` with a generic mapping that owns the
  semantics:

  ```rust
  pub const NETWORK_LOOPBACK_ACTION_CLASS: &str = "network.loopback"; // moved here

  pub fn audit_payload_for(msg: &RunAuditMessage) -> AuditPayload {
      let (action, decision, deny_reason, resource) = match &msg.event {
          RunAuditEvent::LoopbackBlocked { dst_ip, dst_port } => (
              NETWORK_LOOPBACK_ACTION_CLASS.to_string(),
              Decision::Deny,
              DenyReason::LoopbackBlocked.to_string(),
              loopback_resource(dst_ip, *dst_port),
          ),
      };
      AuditPayload { session_id: msg.session_id.clone(), agent_id: msg.agent_id.clone(),
                     token_id: String::new(), action, resource, decision, deny_reason, ..zeros }
  }
  ```

  `loopback_resource` is the former `BlockedLoopbackReport::resource()` bracket
  logic, moved here.
- `socket_path_in` filename → `run-audit.sock`. `lib.rs`: `pub mod` rename.
- Tests: rename to message-based; add a per-variant mapping assertion
  (`audit_payload_for` for `LoopbackBlocked` → `network.loopback` DENY).

### 3. `firma` service — `crates/firma/src/services/sidecar.rs`

- `spawn_egress_report_listener` → `spawn_run_audit_listener`; read
  `FIRMA_RUN_AUDIT_SOCK`; call `firma_sidecar::run_audit_ingest::spawn_listener`.
- Rename the local handle/task bindings (`egress_report_handle`/`_task`).

### 4. `firma-run` producer

- `egress_guard.rs`: import `RunAuditMessage`/`RunAuditEvent`; rename
  `ReportTarget` → `AuditChannel` (same fields). `report_block` → `report_event`
  builds `RunAuditMessage { session_id, agent_id, event:
  RunAuditEvent::LoopbackBlocked { dst_ip: addr.ip().to_string(), dst_port:
  addr.port() } }` and writes the JSON line.
- `routing.rs` `start_loopback_guard`: construct `AuditChannel` via
  `firma_sidecar::run_audit_ingest::socket_path_in(...)`.
- `sidecar/supervisor.rs`: set env `FIRMA_RUN_AUDIT_SOCK` to
  `req.marker_dir.join("run-audit.sock")`; update the mirror comment.

### 5. Docs

- `docs/markdown/firma_action_class_registry.md`: note `network.loopback` is the
  first message kind of the `firma run` audit channel (`RunAuditEvent`).
- `docs-site/public/llms.txt` + `concepts/sandbox.md`: env var rename
  (`FIRMA_RUN_AUDIT_SOCK`) and one line that loopback blocks are one message type
  of a general `firma run`→Sidecar audit channel.
- This plan's "future producers" list stays as the extension guide.

## Reuse

- The listener/framing/channel wiring already exists — only the parsed type and
  the payload-mapping function change.
- `AuditPayload` / `EventBuilder` signing path is untouched
  (`crates/firma-sidecar/src/audit/builder.rs`).

## Verification

- `cargo nextest run -p firma-core -p firma-sidecar -p firma-run -p firma` —
  all green, including the renamed ingest tests and the new mapping test.
- `cargo test --doc -p firma-core` — envelope/variant round-trip.
- `cargo clippy --workspace --lib --bins` clean; `dprint check` clean.
- Grep guard: no remaining `BlockedLoopbackReport`,
  `FIRMA_SIDECAR_EGRESS_REPORT_SOCK`, `egress-report.sock`, or `egress_report`
  module references outside history.
- Behavior unchanged: the Phase 2 e2e (`firma run` blocks a loopback connect →
  signed `network.loopback` DENY in `firma monitor`) still passes with the new
  socket name.
