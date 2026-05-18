# FIR-111 Matrix Summary

Output dir: `matrix/`

## Kernel Probe

```
kernel_release=6.17.9-76061709-generic
kernel_version=#202511241048~1764704751~22.04~b24b425 SMP PREEMPT_DYNAMIC Tue D
actions_avail=kill_process kill_thread trap errno user_notif trace log allow
actions_logged=kill_process kill_thread trap errno user_notif trace log
user_notif_supported=true
seccomp_header_present=true
seccomp_notif_addfd_symbol=true
```

## Scenario Results

| Scenario | Successes | Failures | p50 ms | p95 ms | p99 ms | avg ms | iter/s | work-units/s | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| baseline | 20 | 0 | 806.695 | 806.987 | 807.071 | 806.761 | 1.240 | 148.743 | `matrix/baseline` |
| seccomp-static | 20 | 0 | 806.875 | 807.213 | 807.542 | 806.927 | 1.239 | 148.712 | `matrix/seccomp-static` |
| unotify-none | 20 | 0 | 1526.526 | 1529.027 | 1530.002 | 1526.821 | 0.655 | 78.595 | `matrix/unotify-none` |
| unotify-startup-unavailable | 0 | 20 | 5.601 | 6.117 | 6.214 | 5.630 | 177.620 | 21314.387 | `matrix/unotify-startup-unavailable` |
| unotify-mid-session-crash | 0 | 20 | 5.611 | 6.862 | 7.729 | 5.781 | 172.982 | 20757.834 | `matrix/unotify-mid-session-crash` |
| unotify-slow-notifier | 20 | 0 | 1531.836 | 1533.309 | 1533.564 | 1531.939 | 0.653 | 78.332 | `matrix/unotify-slow-notifier` |

Raw run index: `matrix/runs.tsv`
