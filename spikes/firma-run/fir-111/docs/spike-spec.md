# FIR-111: Linux Local-Command Syscall Enforcement Spike

Status: completed\
Owners: Runtime team\
Branch: `dario/fir-111-linux-local-command-syscall-enforcement-spike-seccomp`\
Last updated: 2026-05-11

## 0. Document map

1. Spike specification (this document):
   `spikes/firma-run/fir-111/docs/spike-spec.md`
2. Final architecture recommendation:
   `spikes/firma-run/fir-111/docs/decision-memo.md`
3. Curated reproducible evidence bundle:
   `spikes/firma-run/fir-111/docs/artifacts/fir-111-20260511-release/`

## 1. Why this spike exists

`firma-run` currently supports optional static seccomp cBPF in the Linux
`bwrap` backend (`seccomp_bpf_path` -> `bwrap --seccomp <fd>`). That gives
kernel-level syscall filtering, but policy is static and not Cedar-driven.

FIR-79 identified the gap for local-command governance at syscall boundary.
Before committing architecture to seccomp-unotify, we need measurable evidence
on correctness, latency, and fail-closed behavior.

## 2. Current implementation baseline (Linux)

Baseline facts from current code:

1. `seccomp_bpf_path` is validated as absolute file path and only accepted on
   backend `bwrap`.
2. Runtime exports `FIRMA_RUN_SECCOMP_BPF_PATH` into launch env.
3. `linux_bwrap` opens the file, clears `FD_CLOEXEC`, and passes it to
   `bwrap --seccomp`.
4. Structural confinement currently centers on namespace + proxy bridge + DNS
   fail-closed path.
5. macOS (`vz`) and Windows (`wsl2`) remain compatibility-mode relative to
   Linux structural path.

Implication: syscall control exists today, but only as static profile-level
filtering and without Cedar decision-time mediation.

## 3. Spike scope and non-goals

Scope:

1. Compare Linux syscall-enforcement approaches for local command execution.
2. Produce reproducible benchmark and failure-mode evidence.
3. Publish architecture decision memo with go/no-go criteria and migration path.

Non-goals:

1. No production rollout of a new syscall mediation engine in this card.
2. No macOS/Windows/BSD implementation in this card.
3. No sidecar policy-plane redesign.

## 4. Candidate approaches to evaluate

1. Static seccomp cBPF baseline (current).
2. seccomp user notification mediation path (spike/prototype only).
3. AppArmor profile-generation path (high-level comparison).
4. eBPF LSM / cgroup-based path (high-level comparison and constraints only).

## 5. Measurement plan

### 5.1 Workload classes

1. Shell-heavy short commands (high `execve` churn).
2. Mixed shell + filesystem metadata commands.
3. Long-running shell loop (steady-state overhead).

### 5.2 Metrics

1. Per-invocation latency: p50/p95/p99.
2. Throughput: commands per second.
3. Failure-mode outcome: fail-closed vs fail-open classification.
4. Policy fidelity notes: decision correctness vs intended Cedar semantics.

### 5.3 Failure-mode matrix

1. Notifier unavailable at startup.
2. Notifier crash/disconnect mid-session.
3. Notifier slow/hung path (timeout behavior).
4. Runtime restart with stale mediation channel.

### 5.4 Correctness matrix

1. Syscall argument attribution boundaries (what is observable at decision time).
2. TOCTOU boundaries (path/FD/state transitions after decision).
3. Decision determinism under concurrent shell subprocesses.

## 6. Planned artifacts (this card)

1. Spike harness scaffolding:
   `spikes/firma-run/fir-111/`.
2. Raw result files under timestamped output directory.
3. Final decision memo:
   `spikes/firma-run/fir-111/docs/decision-memo.md`.
4. Durable artifact bundle:
   `spikes/firma-run/fir-111/docs/artifacts/fir-111-20260511-release/`.

Current harness entrypoints:

1. `spikes/firma-run/fir-111/run.sh`
2. `spikes/firma-run/fir-111/run-matrix.sh`
3. `spikes/firma-run/fir-111/probe-kernel-seccomp.sh`
4. `spikes/firma-run/fir-111/generate-decision-memo-input.sh`
5. Real unotify prototype runner:
   `spikes/firma-run/fir-111/unotify-prototype/seccomp_unotify_runner.c`

## 7. Go/No-go gates (initial)

These gates are intentionally explicit so implementation cards can inherit them:

1. Latency gate: no severe interactive regression in shell-heavy path
   (threshold to be finalized with measured baseline).
2. Fail-closed gate: all tested notifier failure modes must terminate/deny
   safely with no bypass path.
3. Correctness gate: known Cedar-fidelity limits and TOCTOU boundaries must be
   documented with concrete syscall examples.
4. Operability gate: notifier lifecycle management must be testable and
   diagnosable in local + CI workflows.

If any gate fails, recommendation must include fallback architecture
(`static seccomp` + complementary controls).

## 8. Timeline for current release window

Given pre-release target next Friday (2026-05-15), this spike should deliver:

1. By Wednesday, 2026-05-13: harness outputs + preliminary recommendation.
2. By Thursday, 2026-05-14: reviewed decision memo + follow-up implementation
   card draft.

## 9. Explicit risks

1. TOCTOU ambiguity in userspace-mediated syscall decisions.
2. Latency regressions from per-syscall userspace roundtrips.
3. Operational fragility if notifier lifecycle is not tightly fail-closed.

## 10. Definition of done for FIR-111

1. Decision memo published and reviewed.
2. Recommendation is actionable (clear next card and fallback).
3. No critical unknowns remain for Linux architecture selection.

## 11. Completion evidence (2026-05-11)

1. Full matrix executed with all required scenarios:
   baseline, seccomp-static, unotify-none, startup-unavailable,
   mid-session-crash, slow-notifier.
2. Reproducible raw outputs are imported in-repo:
   `spikes/firma-run/fir-111/docs/artifacts/fir-111-20260511-release/matrix/`.
3. Release-mode matrix is authoritative for final go/no-go; debug-mode matrix
   is retained as supporting diagnostic evidence.
4. Decision memo generated and finalized:
   `spikes/firma-run/fir-111/docs/decision-memo.md`.
5. Acceptance criteria are met:
   reproducible methodology, fail-closed outcomes documented, Cedar-fidelity
   caveats with concrete examples, and go/no-go + migration direction.

## 12. Follow-up implementation cards (recommended)

1. Static-policy generation path: compile approved Cedar intent subsets into
   versioned static seccomp deny artifacts for Linux.
2. Regression guardrails: add CI benchmark checks on shell-heavy workload
   (baseline vs seccomp-static overhead budget and fail-closed checks).
3. Optional unotify auxiliary track: keep non-authoritative scope limited to
   bounded emulation/observability with explicit lifecycle tests.
