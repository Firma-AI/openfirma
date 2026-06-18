# FIR-111 Decision Memo Input

Generated: 2026-05-11T14:42:58Z UTC

Matrix directory: `spikes/firma-run/fir-111/docs/artifacts/fir-111-20260511-final/matrix`

## Benchmark Table

| Scenario                    | Mode              | p50 ms   | p95 ms   | p99 ms   | avg ms   | iter/s  | work-units/s | successes | failures |
| --------------------------- | ----------------- | -------- | -------- | -------- | -------- | ------- | ------------ | --------- | -------- |
| baseline                    | baseline          | 808.457  | 809.927  | 812.365  | 808.768  | 1.236   | 148.374      | 20        | 0        |
| seccomp-static              | seccomp-static    | 808.784  | 909.153  | 910.040  | 818.952  | 1.221   | 146.529      | 20        | 0        |
| unotify-none                | unotify-prototype | 1527.778 | 1532.005 | 1632.576 | 1533.240 | 0.652   | 78.266       | 20        | 0        |
| unotify-startup-unavailable | unotify-prototype | 5.304    | 5.764    | 6.056    | 5.337    | 187.368 | 22484.121    | 0         | 20       |
| unotify-mid-session-crash   | unotify-prototype | 5.377    | 5.708    | 5.753    | 5.328    | 187.679 | 22521.466    | 0         | 20       |
| unotify-slow-notifier       | unotify-prototype | 1532.316 | 1533.964 | 1534.402 | 1532.554 | 0.653   | 78.301       | 20        | 0        |

## Failure-Mode Classification

| Scenario                    | Expected behavior      | Observed signal             |
| --------------------------- | ---------------------- | --------------------------- |
| baseline                    | normal execution       | not a failure-mode scenario |
| seccomp-static              | normal execution       | not a failure-mode scenario |
| unotify-none                | normal execution       | not a failure-mode scenario |
| unotify-startup-unavailable | fail-closed            | non-zero exits observed     |
| unotify-mid-session-crash   | fail-closed            | non-zero exits observed     |
| unotify-slow-notifier       | bounded delay, no hang | completed with zero exits   |
