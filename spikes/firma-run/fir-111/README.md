# FIR-111 Spike Harness (Linux)

This folder contains reproducible scaffolding for the FIR-111 Linux syscall
enforcement spike.

It is intentionally lightweight: it does not implement a production mediation
engine. It standardizes how we collect comparable latency/failure data while we
evaluate architecture options.

## Files

- `RUNBOOK.md`: card-oriented execution guide (from prerequisites to memo).
- `run.sh`: spike runner (baseline + static-seccomp mode, pluggable for future
  seccomp-unotify prototype mode).
- `run-matrix.sh`: executes the full scenario matrix and produces a summary.
- `probe-kernel-seccomp.sh`: probes Linux seccomp/user_notif capabilities.
- `generate-decision-memo-input.sh`: converts matrix outputs into memo-ready
  markdown input.
- `generate-static-seccomp-bpf.sh`: generates a valid static seccomp cBPF file
  for `bwrap --seccomp`.
- `workloads/shell-heavy.sh`: default shell-heavy workload used for repeated
  command execution benchmarks.
- `unotify-prototype/seccomp_unotify_runner.c`: Linux seccomp-unotify
  prototype runner (real notifier path).
- `adapters/unotify-runner-firma.sh`: compiles and runs the C prototype,
  wrapping `firma run` command execution.
- `docs/spike-spec.md`: spike scope, goals, acceptance criteria, completion evidence.
- `docs/decision-memo.md`: final Linux architecture recommendation from spike data.
- `docs/artifacts/`: canonical FIR-111 evidence bundle used by the decision memo.

## Quick start

From repo root:

```bash
spikes/firma-run/fir-111/run.sh --mode baseline
```

Static seccomp comparison:

```bash
spikes/firma-run/fir-111/run.sh \
  --mode seccomp-static \
  --seccomp-bpf-path /absolute/path/to/seccomp.bpf
```

Unotify prototype mode (with adapter):

```bash
spikes/firma-run/fir-111/run.sh \
  --mode unotify-prototype \
  --unotify-runner spikes/firma-run/fir-111/adapters/unotify-runner-firma.sh
```

Full matrix:

```bash
SPIKE_DIR="${FIR_SPIKE_OUTPUT_DIR:-$PWD/.spike-output}"
spikes/firma-run/fir-111/run-matrix.sh \
  --firma-bin target/debug/firma \
  --seccomp-bpf-path "$SPIKE_DIR/seccomp-allow-all.bpf" \
  --unotify-runner spikes/firma-run/fir-111/adapters/unotify-runner-firma.sh
```

Release matrix (recommended for final go/no-go decision):

```bash
SPIKE_DIR="${FIR_SPIKE_OUTPUT_DIR:-$PWD/.spike-output}"
cargo build -p firma --release
spikes/firma-run/fir-111/run-matrix.sh \
  --firma-bin target/release/firma \
  --seccomp-bpf-path "$SPIKE_DIR/seccomp-allow-all.bpf" \
  --unotify-runner spikes/firma-run/fir-111/adapters/unotify-runner-firma.sh
```

Generate a static seccomp file:

```bash
SPIKE_DIR="${FIR_SPIKE_OUTPUT_DIR:-$PWD/.spike-output}"
spikes/firma-run/fir-111/generate-static-seccomp-bpf.sh \
  --output "$SPIKE_DIR/seccomp-allow-all.bpf" \
  --mode allow-all
```

Toggle unotify prototype policy mode:

```bash
FIR_UNOTIFY_POLICY_MODE=deny-openat \
spikes/firma-run/fir-111/run.sh \
  --mode unotify-prototype \
  --unotify-runner spikes/firma-run/fir-111/adapters/unotify-runner-firma.sh
```

Tune slow-notifier behavior (defaults: `5ms`, first `1` notification only):

```bash
FIR_UNOTIFY_SLOW_DELAY_MS=5 \
FIR_UNOTIFY_SLOW_MAX_NOTIFS=1 \
spikes/firma-run/fir-111/run.sh \
  --mode unotify-prototype \
  --failure-mode slow-notifier \
  --unotify-runner spikes/firma-run/fir-111/adapters/unotify-runner-firma.sh
```

## Outputs

Each run writes:

- `summary.txt`: aggregate metrics and run metadata.
- `results.jsonl`: per-iteration samples (`elapsed_ms`, `exit_code`, stderr/stdout logs).

`summary.txt` includes latency percentiles plus throughput:

- `iterations_per_sec`
- `work_units_per_sec` (`iterations * inner_loops` normalized per second)

Default output base:

`<spike-output-dir>/<timestamp>/`

Default is `<repo>/.spike-output/<timestamp>/`. Override with
`FIR_SPIKE_OUTPUT_DIR=/your/path`.

Matrix runs produce:

- `runs.tsv`: scenario -> output directory index.
- `matrix-summary.md`: benchmark and failure-mode summary table.
- `kernel-seccomp-probe.txt`: host capability snapshot.

Generate memo input:

```bash
SPIKE_DIR="${FIR_SPIKE_OUTPUT_DIR:-$PWD/.spike-output}"
LATEST_MATRIX="$(ls -1dt "$SPIKE_DIR"/matrix-* | head -n 1)"
spikes/firma-run/fir-111/generate-decision-memo-input.sh \
  --matrix-dir "$LATEST_MATRIX" \
  --out "$LATEST_MATRIX/decision-memo-input.md"
```

## Notes

1. Linux-only.
2. Requires `cargo` and `bwrap`.
3. `seccomp-static` mode requires a valid compiled cBPF file compatible with
   `bwrap --seccomp`.
4. `unotify-prototype` mode expects a runner executable that accepts:
   `--workload`, `--inner-loops`, `--profile`, `--sidecar-endpoint`,
   `--failure-mode`.
5. `adapters/unotify-runner-firma.sh` requires a C compiler (`cc`/`gcc`) and
   Linux seccomp user-notif headers.
6. `adapters/unotify-runner-firma.sh` is the real prototype path.
