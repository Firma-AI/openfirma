# FIR-111 Runbook: Execute the Spike End-to-End

This runbook maps the card requirements directly to executable steps.

## 1. Prerequisites

Linux host required.

Required tools:

1. `bwrap`
2. `cc` or `gcc`
3. `cargo`
4. `python3`

Confirm kernel capability:

```bash
spikes/firma-run/fir-111/probe-kernel-seccomp.sh --format text
```

You should see `user_notif_supported=true`.

## 2. Build `firma` binaries

```bash
cargo build -p firma
cargo build -p firma --release
```

Debug binary:

```text
target/debug/firma
```

Release binary:

```text
target/release/firma
```

## 3. Real unotify prototype smoke test

The following validates that the real seccomp-unotify prototype runner compiles
and executes:

```bash
spikes/firma-run/fir-111/adapters/unotify-runner-firma.sh \
  --firma-bin /bin/true \
  --workload spikes/firma-run/fir-111/workloads/shell-heavy.sh \
  --profile generic \
  --sidecar-endpoint tcp:127.0.0.1:1 \
  --failure-mode none
```

This smoke test bypasses real `firma run` behavior (by using `/bin/true`) and
only confirms prototype runner wiring.

## 4. Execute matrix (real spike)

Generate a valid static seccomp cBPF file first:

```bash
SPIKE_DIR="${FIR_SPIKE_OUTPUT_DIR:-$PWD/.spike-output}"
spikes/firma-run/fir-111/generate-static-seccomp-bpf.sh \
  --output "$SPIKE_DIR/seccomp-allow-all.bpf" \
  --mode allow-all
```

If you already have a valid static seccomp cBPF path:

```bash
SPIKE_DIR="${FIR_SPIKE_OUTPUT_DIR:-$PWD/.spike-output}"
spikes/firma-run/fir-111/run-matrix.sh \
  --firma-bin target/debug/firma \
  --seccomp-bpf-path "$SPIKE_DIR/seccomp-allow-all.bpf"
```

If static cBPF file is not available yet, run without it (static scenario will
be skipped, and you can re-run later when file is available):

```bash
spikes/firma-run/fir-111/run-matrix.sh
```

Run release profile matrix (required for final decision):

```bash
SPIKE_DIR="${FIR_SPIKE_OUTPUT_DIR:-$PWD/.spike-output}"
spikes/firma-run/fir-111/run-matrix.sh \
  --firma-bin target/release/firma \
  --seccomp-bpf-path "$SPIKE_DIR/seccomp-allow-all.bpf"
```

By default, matrix will use:

```text
spikes/firma-run/fir-111/adapters/unotify-runner-firma.sh
```

Recommended slow-notifier tuning to avoid very long runs:

```bash
export FIR_UNOTIFY_SLOW_DELAY_MS=5
export FIR_UNOTIFY_SLOW_MAX_NOTIFS=1
```

## 5. Optional policy-mode run for correctness boundary checks

Force notifier to deny `openat` and capture behavior:

```bash
FIR_UNOTIFY_POLICY_MODE=deny-openat \
spikes/firma-run/fir-111/run.sh \
  --mode unotify-prototype \
  --unotify-runner spikes/firma-run/fir-111/adapters/unotify-runner-firma.sh
```

This is useful for documenting syscall-level policy semantics and caveats.

## 6. Generate decision-memo input artifact

```bash
SPIKE_DIR="${FIR_SPIKE_OUTPUT_DIR:-$PWD/.spike-output}"
LATEST_MATRIX="$(ls -1dt "$SPIKE_DIR"/matrix-* | head -n 1)"
spikes/firma-run/fir-111/generate-decision-memo-input.sh \
  --matrix-dir "$LATEST_MATRIX" \
  --out "$LATEST_MATRIX/decision-memo-input.md"
```

## 7. Artifacts and where they satisfy card acceptance criteria

Generated under:

`<spike-output-dir>/matrix-<timestamp>/` (default:
`<repo>/.spike-output/matrix-<timestamp>/`)

Key files:

1. `kernel-seccomp-probe.txt`
2. `runs.tsv`
3. `matrix-summary.md`
4. `<scenario>/results.jsonl` (raw per-iteration output)
5. `<scenario>/summary.txt` (latency + throughput + failure stats)
6. `decision-memo-input.md`

Acceptance criteria mapping:

1. Reproducible methodology + raw outputs:
   `run-matrix.sh` + `results.jsonl` + `summary.txt`.
2. Fail-closed behavior for tested failure modes:
   unotify scenarios in `matrix-summary.md` and per-scenario `summary.txt` /
   `results.jsonl`.
3. Cedar-fidelity caveats with concrete examples:
   document from `deny-openat` behavior and notifier semantics in decision memo.
4. Final recommendation + migration plan:
   update architecture memo with benchmark/failure evidence.

Decision rule:

1. Use release-mode matrix as the authoritative go/no-go dataset.
2. Keep debug-mode matrix as diagnostic/supporting data only.

## 8. Finalize the architecture memo

Update:

1. `spikes/firma-run/fir-111/docs/decision-memo.md`

with:

1. measured p50/p95/p99 and throughput deltas,
2. failure-mode outcomes (`startup-unavailable`, `mid-session-crash`,
   `slow-notifier`),
3. explicit go/no-go recommendation and fallback architecture.

## 9. Publish final evidence

For this card, the canonical evidence set is already stored in:

```text
spikes/firma-run/fir-111/docs/artifacts/fir-111-20260511-release/
```

For future spikes, keep the same evidence shape:

1. matrix-level files (`matrix-summary.md`, `runs.tsv`, `kernel-seccomp-probe.txt`,
   `decision-memo-input.md`),
2. per-scenario `summary.txt`,
3. per-scenario `results.jsonl`.
