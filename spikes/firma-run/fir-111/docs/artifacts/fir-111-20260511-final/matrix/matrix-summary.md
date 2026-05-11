# FIR-111 Matrix Summary

Output dir: `/tmp/fir-111-spike/matrix-20260511T143402Z`

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
| baseline | 20 | 0 | 808.457 | 809.927 | 812.365 | 808.768 | 1.236 | 148.374 | `/tmp/fir-111-spike/matrix-20260511T143402Z/baseline` |
| seccomp-static | 20 | 0 | 808.784 | 909.153 | 910.040 | 818.952 | 1.221 | 146.529 | `/tmp/fir-111-spike/matrix-20260511T143402Z/seccomp-static` |
| unotify-none | 20 | 0 | 1527.778 | 1532.005 | 1632.576 | 1533.240 | 0.652 | 78.266 | `/tmp/fir-111-spike/matrix-20260511T143402Z/unotify-none` |
| unotify-startup-unavailable | 0 | 20 | 5.304 | 5.764 | 6.056 | 5.337 | 187.368 | 22484.121 | `/tmp/fir-111-spike/matrix-20260511T143402Z/unotify-startup-unavailable` |
| unotify-mid-session-crash | 0 | 20 | 5.377 | 5.708 | 5.753 | 5.328 | 187.679 | 22521.466 | `/tmp/fir-111-spike/matrix-20260511T143402Z/unotify-mid-session-crash` |
| unotify-slow-notifier | 20 | 0 | 1532.316 | 1533.964 | 1534.402 | 1532.554 | 0.653 | 78.301 | `/tmp/fir-111-spike/matrix-20260511T143402Z/unotify-slow-notifier` |

Raw run index: `/tmp/fir-111-spike/matrix-20260511T143402Z/runs.tsv`
