# Interception Load Stress Guide (HTTP)

This guide describes a reproducible way to validate fail-closed behavior under concurrent load for the `firma-sidecar` HTTP interception pipeline.

## What is covered

- 100 concurrent protected HTTP requests complete with a concrete `EnforcementDecision`
- no protected request returns `Passthrough`
- Stage 2 timeout returns `DENY: EnforcementTimeout`
- unavailable policy bundle returns `DENY: FailClosed`
- stale policy bundle returns `DENY: PolicyBundleStale`
- basic threaded-read race smoke test for shared pipeline access
- shared state mutation stress over policy set, revocation cache, and session counters

## Test suite

Run the stress suite only:

```bash
cargo test -p firma-sidecar --test interception_stress -- --nocapture
```

Run only shared state mutation stress:

```bash
cargo test -p firma-sidecar --test interception_stress stress_shared_state_mutation_produces_only_valid_decisions -- --exact --nocapture
```

Run only the 100-concurrency test:

```bash
cargo test -p firma-sidecar --test interception_stress stress_100_concurrent_requests_no_passthrough -- --exact --nocapture
```

Run only timeout fail-closed behavior:

```bash
cargo test -p firma-sidecar --test interception_stress stage2_timeout_denies_with_enforcement_timeout -- --exact --nocapture
```

## Reliability notes

- timeout simulation uses `tokio::time::pause` + `tokio::time::advance` to avoid wall-clock flakiness
- tests use a protected host route (`api.openai.com`) so any `Passthrough` is a correctness bug
- each spawned task is bounded by `tokio::time::timeout` to fail fast on hangs

## Data-race checks (recommended)

The current test suite includes a threaded shared-read stress test (`threaded_reads_do_not_panic_or_passthrough`).

For deeper race checking, run Loom model checking:

```bash
cargo test -p firma-sidecar --test loom_shared_state --features loom-tests -- --nocapture
```

Optionally run Miri on the stress target:

```bash
cargo +nightly miri test -p firma-sidecar --test interception_stress
```

If Miri is not installed yet:

```bash
rustup +nightly component add miri
cargo +nightly miri setup
```

Shortcut:

```bash
make stress-miri
```

## Invariants to preserve

- protected traffic must never bypass Stage 1 + Stage 2
- policy unavailability failures return `FailClosed`, never fallback allow
- policy freshness failures return `PolicyBundleStale` (fail-closed class), never fallback allow
- policy evaluation timeout must fail closed (`EnforcementTimeout`)
- policy evaluator errors are treated as fail-closed (`FailClosed`)
