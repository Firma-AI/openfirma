# FIR-111 Decision Memo Input

Generated: 2026-05-11T16:05:06Z UTC

Matrix directory: `matrix/`

## Benchmark Table

| Scenario                    | Mode              | p50 ms   | p95 ms   | p99 ms   | avg ms   | iter/s  | work-units/s | successes | failures |
| --------------------------- | ----------------- | -------- | -------- | -------- | -------- | ------- | ------------ | --------- | -------- |
| baseline                    | baseline          | 806.695  | 806.987  | 807.071  | 806.761  | 1.240   | 148.743      | 20        | 0        |
| seccomp-static              | seccomp-static    | 806.875  | 807.213  | 807.542  | 806.927  | 1.239   | 148.712      | 20        | 0        |
| unotify-none                | unotify-prototype | 1526.526 | 1529.027 | 1530.002 | 1526.821 | 0.655   | 78.595       | 20        | 0        |
| unotify-startup-unavailable | unotify-prototype | 5.601    | 6.117    | 6.214    | 5.630    | 177.620 | 21314.387    | 0         | 20       |
| unotify-mid-session-crash   | unotify-prototype | 5.611    | 6.862    | 7.729    | 5.781    | 172.982 | 20757.834    | 0         | 20       |
| unotify-slow-notifier       | unotify-prototype | 1531.836 | 1533.309 | 1533.564 | 1531.939 | 0.653   | 78.332       | 20        | 0        |

## Failure-Mode Classification

| Scenario                    | Expected behavior      | Observed signal             |
| --------------------------- | ---------------------- | --------------------------- |
| baseline                    | normal execution       | not a failure-mode scenario |
| seccomp-static              | normal execution       | not a failure-mode scenario |
| unotify-none                | normal execution       | not a failure-mode scenario |
| unotify-startup-unavailable | fail-closed            | non-zero exits observed     |
| unotify-mid-session-crash   | fail-closed            | non-zero exits observed     |
| unotify-slow-notifier       | bounded delay, no hang | completed with zero exits   |
