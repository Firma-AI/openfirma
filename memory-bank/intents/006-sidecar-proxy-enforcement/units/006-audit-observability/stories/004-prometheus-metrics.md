---
id: 004-prometheus-metrics
unit: 006-audit-observability
intent: 006-sidecar-proxy-enforcement
status: draft
priority: should
created: 2026-04-05T12:00:00Z
assigned_bolt: null
implemented: false
---

# Story: 004-prometheus-metrics

## User Story

**As an** operator
**I want** Prometheus-compatible metrics so that I can monitor Sidecar health, enforcement decisions, and latency in real-time
**So that** I can detect anomalies, set alerts, and maintain operational visibility over the enforcement layer

## Acceptance Criteria

- [ ] **Given** the Sidecar is running, **When** a Prometheus scraper sends `GET /metrics`, **Then** the response is in Prometheus exposition format (`text/plain; version=0.0.4; charset=utf-8`)
- [ ] **Given** enforcement decisions are being made, **When** `/metrics` is scraped, **Then** the counter `firma_decisions_total{stage, decision, reason}` reflects the cumulative count of all ALLOW, DENY, and ABORT decisions, labeled by enforcement stage (stage1, stage2), decision outcome, and reason code
- [ ] **Given** enforcement is processing requests, **When** `/metrics` is scraped, **Then** the histogram `firma_stage1_latency_seconds` reports the distribution of Stage 1 (capability validation) latency
- [ ] **Given** enforcement is processing requests, **When** `/metrics` is scraped, **Then** the histogram `firma_stage2_latency_seconds` reports the distribution of Stage 2 (Cedar policy evaluation) latency
- [ ] **Given** enforcement is processing requests, **When** `/metrics` is scraped, **Then** the histogram `firma_enforcement_latency_seconds` reports the distribution of total end-to-end enforcement latency (Stage 1 + Stage 2 combined)
- [ ] **Given** active proxy connections, **When** `/metrics` is scraped, **Then** the gauge `firma_active_connections` reports the current number of active agent-to-proxy connections
- [ ] **Given** a loaded policy bundle, **When** `/metrics` is scraped, **Then** the gauge `firma_policy_bundle_age_seconds` reports the time since the last successful policy bundle load/refresh
- [ ] **Given** a revocation cache, **When** `/metrics` is scraped, **Then** the gauge `firma_revocation_cache_size` reports the current number of entries in the revocation cache
- [ ] **Given** a loaded policy bundle, **When** `/metrics` is scraped, **Then** the info metric `firma_policy_bundle_version` reports the version string of the currently active policy bundle

## Technical Notes

- Use the `prometheus` crate or the `metrics` + `metrics-exporter-prometheus` crate family for metric registration and exposition
- The `/metrics` endpoint can be served on:
  - The Pingora admin port (if Pingora exposes one), or
  - A separate HTTP listener on a configurable port (e.g., `:9090`) using `axum` or `warp`
  - Must not be served on the main proxy port (`:8080`) to avoid interference with proxied traffic
- Histogram bucket configuration for latency metrics:
  - Stage 1: buckets focused on microsecond range (0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01)
  - Stage 2: buckets focused on sub-millisecond range (0.00005, 0.0001, 0.0002, 0.0005, 0.001, 0.005)
  - End-to-end: buckets spanning microseconds to low milliseconds (0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05)
- Counter label cardinality considerations:
  - `stage` labels: `stage1`, `stage2`, `connector`, `response_parser`
  - `decision` labels: `allow`, `deny`, `abort`
  - `reason` labels: the full set of reason codes from FR-11; keep cardinality bounded
- `firma_policy_bundle_version` is an info metric (constant gauge with a label): `firma_policy_bundle_version{version="v1.2.3"} 1`
- Metric registration should happen at startup; metric recording happens inline on the enforcement hot path (incrementing a counter or observing a histogram is < 1us)
- Configuration (approximate TOML):
  ```toml
  [metrics]
  enabled = true
  listen_address = "0.0.0.0:9090"
  ```

## Dependencies

### Requires

- None (metrics infrastructure is standalone; metric values are populated by other components)

### Enables

- Operator dashboards (Grafana, Datadog, etc.)
- Alerting on enforcement anomalies (spike in DENY rate, latency regression)
- SLA monitoring for enforcement latency targets

## Edge Cases

| Scenario | Expected Behavior |
| -------- | ----------------- |
| No requests processed yet (fresh startup) | All counters at 0; histograms empty; gauges at initial values (0 connections, bundle age from startup) |
| Prometheus scraper not configured (no one scrapes /metrics) | Endpoint still available; metrics still recorded internally; no resource waste beyond metric storage |
| Very high scrape frequency (every 1s) | Endpoint serves current snapshot each time; no significant overhead |
| Metrics endpoint port conflicts with another process | Fail-fast at startup with bind error |
| Policy bundle not yet loaded at scrape time | `firma_policy_bundle_version{version="none"} 1`; `firma_policy_bundle_age_seconds` reports time since startup |
| Label value contains special characters | Prometheus client library handles escaping per exposition format spec |
| Counter overflow (extremely high throughput over months) | Prometheus counters are f64; overflow is practically impossible (~10^308) |
| Metrics disabled in configuration | /metrics endpoint not started; no metric recording overhead; other components check metrics-enabled flag before recording |

## Out of Scope

- Grafana dashboard definitions or provisioning
- Alert rule definitions (operator responsibility)
- Push-based metric delivery (Prometheus pull model only in V1)
- OpenTelemetry metrics export (future enhancement)
- Per-agent or per-session metric breakdowns (label cardinality concern)
- Custom metric registration by community plugins
- Metric persistence across restarts (Prometheus handles this server-side)
