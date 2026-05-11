# FIR-111: Linux Syscall Enforcement Architecture Decision Memo

Status: final recommendation  
Date: 2026-05-11  
Owner: Runtime team  
Scope: Linux local-command syscall enforcement path for `firma run`

## 0. Document map

1. Spike specification:
   `spikes/firma-run/fir-111/docs/spike-spec.md`
2. Evidence bundle used for this memo:
   `spikes/firma-run/fir-111/docs/artifacts/fir-111-20260511-release/`
3. Spike harness implementation:
   `spikes/firma-run/fir-111/`

## 1. Decision summary

Final recommendation:

1. Do not adopt seccomp-unotify as the primary Cedar security-policy
   enforcement primitive for Linux local-command governance.
2. Keep static kernel-enforced deny controls (seccomp cBPF baseline today,
   plus targeted expansion options) as the security-critical foundation.
3. Evaluate seccomp-unotify only as a narrow auxiliary mechanism where a
   privileged supervisor performs bounded syscall emulation, with explicit
   fail-closed lifecycle and documented TOCTOU limits.

## 2. Context

Current implementation:

1. `firma-run` Linux backend (`bwrap`) optionally passes compiled seccomp cBPF
   via `seccomp_bpf_path`.
2. Syscall enforcement is static and profile-driven.
3. Cedar decisions currently govern network/interceptor policy planes, not
   kernel syscall mediation.

Target requirement from FIR-79/FIR-111:

1. Evaluate feasibility of Cedar-aligned syscall enforcement.
2. Preserve fail-closed behavior under notifier outages/crashes.
3. Avoid unsound argument-attribution and TOCTOU behavior.

## 3. Option analysis

### Option A: static seccomp baseline

Pros:

1. Kernel-enforced deterministic deny behavior.
2. No userspace mediation loop on each trapped syscall.
3. Operationally simpler fail-closed properties.

Cons:

1. Limited runtime dynamism versus Cedar intent.
2. Harder to express contextual rules without regeneration/reload workflow.

### Option B: seccomp-unotify mediation

Pros:

1. Userspace observer can inspect syscall metadata and choose response.
2. Supports emulation-style supervisor flows for selected syscalls.

Cons:

1. Upstream seccomp_unotify documentation explicitly warns it is not designed
   as a general security-policy mechanism; TOCTOU exposure is documented for
   continue-path semantics.
2. Adds notifier lifecycle complexity (startup availability, crash/disconnect,
   latency backpressure).
3. Introduces potentially significant per-syscall roundtrip overhead.

### Option C: AppArmor profile-generation path

Pros:

1. Mature Linux LSM policy mechanism.
2. Better alignment with kernel-native security policy than userspace notify.

Cons:

1. Host policy management and profile lifecycle complexity.
2. Translation boundary from Cedar intent requires strict mapping discipline.

### Option D: eBPF LSM/cgroup path (high-level)

Pros:

1. Strong kernel-plane enforcement potential with richer attachment points.
2. May better support broader process/network attribution controls.

Cons:

1. Higher implementation complexity and operational prerequisites.
2. Not realistic for immediate pre-release timeline.

## 4. Evidence and inference

Evidence used:

1. Current `firma-run` Linux code path and config validation.
2. FIR architecture/security docs in-repo.
3. Linux seccomp_unotify primary documentation.
4. FIR-111 matrix artifacts:
   `spikes/firma-run/fir-111/docs/artifacts/fir-111-20260511-release/matrix/`

Note:

1. Attached release-mode matrix artifacts are authoritative for final
   architecture go/no-go.
2. Debug-mode historical artifacts are retained separately for diagnostic
   context only.

### 4.1 Benchmark summary (shell-heavy workload)

| Scenario | Mode | p50 ms | p95 ms | p99 ms | avg ms | iter/s | work-units/s |
| --- | --- | --- | --- | --- | --- | --- | --- |
| baseline | baseline | 806.695 | 806.987 | 807.071 | 806.761 | 1.240 | 148.743 |
| static seccomp | seccomp-static | 806.875 | 807.213 | 807.542 | 806.927 | 1.239 | 148.712 |
| unotify | unotify-prototype | 1526.526 | 1529.027 | 1530.002 | 1526.821 | 0.655 | 78.595 |
| unotify (slow) | unotify-prototype/slow | 1531.836 | 1533.309 | 1533.564 | 1531.939 | 0.653 | 78.332 |

Observed deltas:

1. Static seccomp avg overhead vs baseline: about `+0.02%`.
2. Unotify avg overhead vs baseline: about `+89.25%` (`~1.9x` slower).
3. Unotify throughput vs baseline: about `0.53x`.

### 4.2 Failure-mode outcomes

| Failure mode | Expected | Observed | Pass/Fail | Notes |
| --- | --- | --- | --- | --- |
| startup unavailable | fail-closed | `exit=63` for all 20/20 | Pass | deterministic startup deny |
| mid-session crash | fail-closed | `exit=64` for all 20/20 | Pass | deterministic runtime deny |
| slow notifier | bounded delay | completes 20/20 with bounded config | Pass | bounded with `FIR_UNOTIFY_SLOW_MAX_NOTIFS=1` |

### 4.3 Correctness boundary notes (Cedar fidelity + TOCTOU)

Concrete spike observations:

1. Policy mode `deny-openat` causes immediate runtime failure (`exit=127`)
   because process loader/startup path requires `openat`; this demonstrates
   coarse syscall controls can break normal runtime behavior without
   argument-level semantics.
2. seccomp-unotify decision flow remains userspace-mediated and subject to the
   documented TOCTOU caveats around continue-path timing windows.
3. Syscall-number-only mediation is insufficient to encode Cedar-like intent
   without additional contextual attribution and robust policy compilation rules.

Inference:

1. Using seccomp-unotify as the primary Cedar security decision engine is
   high-risk without strong compensating kernel constraints, because the
   documented TOCTOU semantics conflict with strict policy guarantees.
2. A safer near-term architecture is static kernel deny as baseline, with any
   userspace notifier path explicitly scoped as auxiliary and non-authoritative
   for core deny invariants.

## 5. Go/No-go gate outcomes

The final FIR-111 recommendation must pass all gates:

1. Latency gate: **Fail** for primary-path use.
   Unotify path shows major overhead versus baseline.
2. Fail-closed gate: **Pass** for tested startup and crash failure modes.
3. Correctness gate: **Pass with caveats**.
   Key fidelity and TOCTOU caveats are explicit and evidenced.
4. Operability gate: **Pass with complexity warning**.
   Harnessed and diagnosable, but lifecycle complexity is materially higher
   than static-kernel enforcement.

## 6. Migration direction

1. Keep static seccomp deny baseline in Linux `bwrap` path.
2. Add structured policy-compilation/generation workflow for static rules where
   Cedar intent must project into syscall deny sets.
3. If unotify remains in scope, restrict it to explicitly enumerated emulation
   cases and enforce fail-closed supervisory controls.

## 7. Follow-up implementation direction

1. Keep Linux static seccomp baseline in `bwrap` path as authoritative
   fail-closed syscall control.
2. Define policy-compilation workflow from approved Cedar intent subsets into
   static kernel deny rules (versioned artifacts).
3. If retaining unotify for future work, scope it to non-authoritative
   observability/auxiliary emulation cases and keep core deny invariants in
   static kernel policy.
4. Prepare separate implementation card for static-policy generation,
   benchmarking guardrails, and regression tests.

## 8. Sources

1. Linux seccomp_unotify manual:
   https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html
2. Linux seccomp filter documentation:
   https://cdn.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html
3. FIR-111 spike spec (repo):
   `spikes/firma-run/fir-111/docs/spike-spec.md`
4. FIR-111 evidence bundle index (repo):
   `spikes/firma-run/fir-111/docs/artifacts/README.md`
