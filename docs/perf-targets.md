# Sidecar performance targets

Component Reference §11 sets per-stage budgets for the enforcement hot
path. This document records the current criterion measurements against
each budget. Numbers are soft gates logged in CI; hard regression gating
via `critcmp` against a stored baseline is tracked as a follow-up.

## Reference hardware

Darwin arm64 (Apple M4 Max, release build).

## Current measurements

| Path                    | Budget    | Bench                               | Measured (median) |
| ----------------------- | --------- | ----------------------------------- | ----------------- |
| Stage 1 p95             | < 1 ms    | `stage1_enforce`                    | 160 ns            |
| Stage 2 p95 (allow)     | < 200 µs  | `cedar_evaluate_allow`              | 58 µs             |
| Stage 2 p95 (deny)      | < 200 µs  | `cedar_evaluate_deny`               | 58 µs             |
| Stage 2 p95 (context)   | < 200 µs  | `cedar_evaluate_context`            | 58 µs             |
| End-to-end overhead p95 | < 3 ms    | `pipeline_enforce`                  | 79 µs             |
| Bundle hot-reload       | < 500 ms  | `cedar_bundle_reload`               | 680 µs            |
| Revocation lookup       | (logged)  | `is_revoked_miss`                   | 930 ns            |
|                         | (logged)  | `is_revoked_hit`                    | 59 ns             |
| Revocation propagation  | < 1 s p99 | covered by stream-integration tests | n/a               |

All budgets currently met with substantial headroom.

## Running benches locally

```bash
just bench
```

Criterion reports are written to `target/criterion/`. Open
`target/criterion/report/index.html` in a browser for interactive
regression plots.

Run a single bench:

```bash
cargo bench -p firma-sidecar --bench pipeline
```

Quick smoke run (CI-style):

```bash
cargo bench -p firma-sidecar --bench pipeline -- --quick
```

## Comparing two runs

```bash
cargo bench --bench pipeline -- --save-baseline before
# ... change code ...
cargo bench --bench pipeline -- --save-baseline after
cargo install critcmp
critcmp before after
```

## CI artifacts

Each GitHub Actions workflow run uploads `target/criterion/**` as the
`criterion-reports` artifact (14-day retention). See the `bench` job in
`.github/workflows/ci.yml`.

## Known gaps

- `benches/bundle_reload.rs` currently measures
  `CedarPolicyEvaluator::from_bundle` plus a first `evaluate()` on the
  new snapshot. Once task 013's `BundleLoader::apply` atomic-swap API
  lands, switch the bench to that real swap path.
- No hard regression gate yet; `critcmp` comparison against a checked-in
  baseline is tracked as a follow-up task.
