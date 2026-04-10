---
id: 003-audit-sinks
unit: 006-audit-observability
intent: 006-sidecar-proxy-enforcement
status: draft
priority: must
created: 2026-04-05T12:00:00Z
assigned_bolt: null
implemented: false
---

# Story: 003-audit-sinks

## User Story

**As an** operator
**I want** audit events emitted to stdout (JSON lines) and/or an append-only file, with async non-blocking delivery
**So that** enforcement is never delayed by audit writes

## Acceptance Criteria

- [ ] **Given** a signed ExecutionEvent and the stdout sink enabled, **When** the event is emitted, **Then** one JSON line is written to stdout, compatible with `jq` and standard log aggregators
- [ ] **Given** a signed ExecutionEvent and the file sink enabled with a configured path, **When** the event is emitted, **Then** the event is appended to the configured file path as a single JSON line
- [ ] **Given** both stdout and file sinks configured, **When** an event is emitted, **Then** the event is delivered to both sinks simultaneously
- [ ] **Given** any enforcement decision (ALLOW, DENY, ABORT), **When** the audit emission runs, **Then** it does not block the enforcement hot path — the event is handed off asynchronously
- [ ] **Given** the Sidecar codebase, **When** a developer implements a new audit sink, **Then** an `AuditSink` trait is available with `emit(event)` and `flush()` methods for community implementations
- [ ] **Given** V1 delivery semantics, **When** the Sidecar crashes unexpectedly, **Then** in-process buffered events that have not yet been written to sinks are lost (best-effort async, no WAL)
- [ ] **Given** the Sidecar receives SIGTERM, **When** graceful shutdown begins, **Then** all pending buffered events are flushed to all active sinks before the process exits

## Technical Notes

- Use `tokio::sync::mpsc` as the async channel between the enforcement hot path and the sink writer task(s)
- The enforcement path sends the signed event into the channel and returns immediately (non-blocking send; bounded channel)
- A dedicated background task reads from the channel and dispatches to all active sinks
- `AuditSink` trait (approximate):
  ```rust
  #[async_trait]
  pub trait AuditSink: Send + Sync {
      async fn emit(&self, event: &ExecutionEvent) -> Result<(), AuditSinkError>;
      async fn flush(&self) -> Result<(), AuditSinkError>;
  }
  ```
- Stdout sink: uses `serde_json::to_string` to serialize the event, then writes to stdout with a trailing newline. Use `tokio::io::stdout()` for non-blocking writes
- File sink: opens the file in append mode at startup. Uses `tokio::fs::OpenOptions` with `.append(true).create(true)`. Writes each event as a JSON line followed by newline. Calls `flush()` after each write (or periodically) to ensure durability
- Bounded channel size should be configurable (default: 10,000 events). If the channel is full, the enforcement path should **drop the event** (not block) and increment a metric counter for dropped events
- On graceful shutdown: close the channel sender side, then drain remaining events from the channel, flush all sinks
- Multi-sink dispatch: iterate over all configured sinks for each event. If one sink fails, log the error and continue to the next sink (partial delivery is better than total loss)
- Configuration (approximate TOML):
  ```toml
  [audit]
  sinks = ["stdout", "file"]
  file_path = "/var/log/firma/audit.jsonl"
  buffer_size = 10000
  ```

## Dependencies

### Requires

- 001-execution-event-schema (provides the ExecutionEvent struct)
- 002-ecdsa-audit-signing (provides signed events)

### Enables

- All enforcement pipeline stories (audit emission is the terminal step of every decision path)
- External log aggregation (stdout JSON lines consumed by fluentd, vector, etc.)
- Forensic analysis (file sink provides a local audit trail)

## Edge Cases

| Scenario | Expected Behavior |
| -------- | ----------------- |
| File sink path does not exist (parent directory missing) | Fail-fast at startup with clear error; do not silently create deep directory structures |
| File sink path exists but is not writable | Fail-fast at startup with permission error |
| File sink disk is full at runtime | Write fails; error logged; event delivered to remaining sinks (stdout); dropped-event metric incremented |
| Stdout is redirected to /dev/null or a closed pipe | Write fails silently or with EPIPE; event delivered to remaining sinks; no crash |
| Event channel is full (backpressure from slow sinks) | Event dropped on the enforcement path (non-blocking); dropped-event counter incremented; enforcement proceeds |
| Extremely high event rate (>50k events/sec) | Channel provides backpressure; dropped events are counted; sinks process as fast as possible |
| Sidecar crashes (SIGKILL, OOM, panic) | Buffered events in the channel are lost; no WAL in V1; this is the accepted best-effort guarantee |
| File grows very large (>1 GB) | No automatic rotation in V1; operator responsibility to configure logrotate or equivalent |
| Sink emit() returns an error for every event | Error logged each time (with rate limiting to avoid log flooding); other sinks still receive events |
| No sinks configured | Valid configuration; events are created and signed but not emitted anywhere; log warning at startup |

## Out of Scope

- WAL-backed durable audit sinks (post-V1 enhancement for at-least-once delivery)
- gRPC streaming audit sinks (post-V1)
- Log file rotation (operator responsibility via external tooling)
- Event batching for sink efficiency (V1 emits one event at a time)
- Sink health checks or circuit breakers
- Event filtering per sink (all sinks receive all events in V1)
- Compression of audit log files
