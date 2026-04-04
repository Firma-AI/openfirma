---
unit: 006-audit-observability
intent: 006-sidecar-proxy-enforcement
phase: inception
status: draft
created: 2026-04-05T12:00:00Z
updated: 2026-04-05T12:00:00Z
---

# Unit Brief: Audit & Observability

## Purpose

Implement the audit event emission system with ECDSA signing and the Prometheus metrics endpoint. Every enforcement decision (ALLOW, DENY, ABORT) emits a signed audit event to configurable sinks. V1 delivery is best-effort async — events buffered in-process are lost on crash.

## Scope

### In Scope

- `ExecutionEvent` struct with all FEP §15 minimum audit fields
- ECDSA signature computation over all event fields
- `AuditSink` trait with two V1 implementations: stdout (JSON lines) and file (append-only)
- Multiple sinks active simultaneously
- Async non-blocking emission (does not block enforcement hot path)
- Best-effort delivery guarantee (V1 — event loss on crash acceptable)
- Prometheus `/metrics` endpoint with exposition format
- Decision counters: `firma_decisions_total{stage, decision, reason}`
- Latency histograms: `firma_stage1_latency_seconds`, `firma_stage2_latency_seconds`, `firma_enforcement_latency_seconds`
- Gauges: `firma_active_connections`, `firma_policy_bundle_age_seconds`, `firma_revocation_cache_size`
- Info: `firma_policy_bundle_version`
- Audit event flushing on graceful shutdown

### Out of Scope

- WAL-backed durable audit sinks (post-V1)
- gRPC streaming audit sinks (post-V1)
- At-least-once delivery guarantees (post-V1)
- Log aggregator integrations beyond stdout/file

---

## Assigned Requirements

| FR | Requirement | Priority |
|----|-------------|----------|
| FR-10 | Audit Emitter | Must |
| FR-13 | Prometheus Metrics | Should |

---

## Domain Concepts

### Key Entities

| Entity | Description | Attributes |
|--------|-------------|------------|
| ExecutionEvent | Audit record for an enforcement decision | event_id (UUID v7), session_id, agent_id, token_id, action_class, resource, decision, deny_reason, enforcement_latency_us, context_hash, bundle_version, registry_version, trace_id, timestamp_ns, signature |
| AuditSink | Trait for event delivery targets | emit(event), flush() |
| StdoutSink | JSON lines to stdout | One line per event, jq-compatible |
| FileSink | Append-only file writes | Configurable path |
| MetricsRegistry | Prometheus metrics collection | Counters, histograms, gauges |

### Key Operations

| Operation | Description | Inputs | Outputs |
|-----------|-------------|--------|---------|
| emit_event | Serialize and sign audit event, send to sinks | ExecutionEvent fields | Signed event delivered to all active sinks |
| sign_event | Compute ECDSA signature over event fields | Event fields, signing key | Signature bytes |
| flush_sinks | Flush pending events (shutdown) | — | All buffered events written |
| record_metric | Update Prometheus metric | Metric name, labels, value | Updated counter/histogram/gauge |

---

## Story Summary

| Metric | Count |
|--------|-------|
| Total Stories | 4 |
| Must Have | 3 |
| Should Have | 1 |
| Could Have | 0 |

### Stories

| Story ID | Title | Priority | Status |
|----------|-------|----------|--------|
| 001-execution-event-schema | ExecutionEvent with all FEP §15 fields | Must | Planned |
| 002-ecdsa-audit-signing | ECDSA signature over event fields | Must | Planned |
| 003-audit-sinks | stdout + file sinks, multi-sink, async non-blocking | Must | Planned |
| 004-prometheus-metrics | /metrics endpoint, counters, histograms, gauges | Should | Planned |

---

## Dependencies

### Depends On

| Unit | Reason |
|------|--------|
| None | Receives events from enforcement pipeline via async channel |

### Depended By

| Unit | Reason |
|------|--------|
| 001-proxy-core | Audit emitter called after every enforcement decision |

### External Dependencies

| System | Purpose | Risk |
|--------|---------|------|
| p256 or ecdsa crate | ECDSA signing | Low |
| prometheus crate | Metrics exposition | Low |

---

## Technical Context

### Suggested Technology

- p256 or ecdsa crate for ECDSA signing
- uuid crate (v7) for event IDs
- serde_json for event serialization
- tokio::sync::mpsc for async event channel
- prometheus or metrics crate for Prometheus exposition
- axum or warp for /metrics HTTP endpoint (or Pingora admin endpoint)

### Integration Points

| Integration | Type | Protocol |
|-------------|------|----------|
| Enforcement Pipeline | Internal | Async channel (tokio mpsc) |
| Prometheus scraper | External | HTTP GET /metrics |
| Log aggregators | External | stdout JSON lines |

---

## Constraints

- Every ALLOW, DENY, and ABORT must emit an event (no silent decision paths)
- All FEP §15 minimum fields present in every event
- ECDSA signature verifiable without Sidecar access (using audit signing public key)
- Audit emission must not block enforcement hot path
- V1: best-effort async only — in-process buffered events lost on crash
- Multiple sinks active simultaneously
- Pending events flushed on graceful shutdown (before process exit)

---

## Success Criteria

### Functional

- [ ] Every decision emits an audit event (no silent paths)
- [ ] All FEP §15 minimum fields present
- [ ] ECDSA signature computed and verifiable
- [ ] stdout sink: one JSON line per event, jq-compatible
- [ ] file sink: append-only to configurable path
- [ ] Multiple sinks active simultaneously
- [ ] Audit emission does not block enforcement
- [ ] /metrics returns Prometheus exposition format
- [ ] All required counters, histograms, and gauges present

### Non-Functional

- [ ] Audit emission overhead < 100us (async handoff)
- [ ] No enforcement latency impact from slow sinks

### Quality

- [ ] Tests verifying ECDSA signature validity
- [ ] Tests verifying all FEP §15 fields present
- [ ] Tests for multi-sink concurrent emission
- [ ] Tests for flush on shutdown

---

## Bolt Suggestions

| Bolt | Type | Stories | Objective |
|------|------|---------|-----------|
| 013-audit-observability | DDD | 001, 002, 003, 004 | Audit emission + ECDSA signing + Prometheus metrics |

---

## Notes

- V1 audit delivery is explicitly best-effort async with possible event loss on crash (per team decision)
- WAL-backed sinks and at-least-once delivery are post-V1 enhancements
- The audit signing key is separate from the CA keypair used for TLS interception
- Prometheus metrics provide real-time observability; audit events provide the durable (best-effort) trail
