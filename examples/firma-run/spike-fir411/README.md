# FIR-411 boundary spike

This is throwaway proof-of-concept code for the `firma run <harness>` boundary
spike (FIR-411). It isn't product code. It exists to answer the spike's design
questions and produce [`FINDING.md`](FINDING.md), and then it gets deleted.

It runs on Linux with the bwrap structural backend, so netns confinement plus a
sidecar-mediated HTTP funnel. Everything runs locally against fake services. No
cloud, no real secrets.

## What is here

| path                 | purpose                                                                  |
| -------------------- | ------------------------------------------------------------------------ |
| `firma.toml`         | self-contained authority, sidecar and run config                         |
| `mapping-rules.toml` | destination mapping (approved-api allowed, sink left out so it's denied) |
| `policies/`          | Cedar bundle (allow external send, forbid credential read)               |
| `issuance-policies/` | permissive issuance policy for the local Mini Authority                  |
| `servers/`           | `approved-api` (checks the injected bearer) and `exfil-sink`             |
| `demos/`             | demos 1 to 3, each run bare and boxed                                    |
| `breakout/`          | five active attacks on the box (b1 to b5)                                |
| `bench-latency.sh`   | per-action and cold-start latency probe                                  |
| `lib/common.sh`      | shared helpers sourced by every script                                   |
| `run-all.sh`         | run everything and print the break-out results table                     |

## Prerequisites

- `cargo build -p firma` (the spike calls `target/debug/firma`).
- `python3` and `bwrap` on `PATH`.
- For the harness-wrapping checks: `opencode` and `pi` on `PATH`.

Install the harnesses (you'll need Node 18 or newer):

```bash
npm i -g opencode-ai                    # binary: opencode
npm i -g @mariozechner/pi-coding-agent  # binary: pi
```

Watch out for the package-name collisions: `@mariozechner/pi`, `@badlogic/pi`,
and `pi-ai` are different packages. The coding agent is
`@mariozechner/pi-coding-agent`.

## Run it

```bash
cargo build -p firma
./run-all.sh
```

Or one at a time:

```bash
bash demos/demo1-credential-leak.sh
bash breakout/b1-bind-mount-watcher.sh
N=50 bash bench-latency.sh
```

Each demo starts the fake services and runs a payload twice, once `bare`
(direct) and once `boxed` (through `firma run`). Then it prints a side-by-side
of what the sink saw. A leak means the sink logged the secret. Blocked means
the sink saw nothing.

## Wrapping a harness directly

The spike adds built-in `opencode` and `pi` profiles. Launch either through the
box:

```bash
CFG="$(pwd)/firma.toml"
firma run --config "$CFG" --profile opencode --authority local --sidecar local -- opencode
firma run --config "$CFG" --profile pi       --authority local --sidecar local -- pi
```

`firma run -- opencode` also auto-selects the `opencode` profile from the
command name, so the explicit `--profile` is optional once a `firma.toml` is in
place.

## Sharp edges (see the finding for detail)

- Pass an **absolute** `--config` path. A relative one breaks the autostarted
  authority's key-file resolution.
- The mapping and the credential `target_host` match the host **including
  port**, so the fixed demo ports (8081/8082) are part of the rules here.
- `*.localhost` resolves to `::1`, so the fake servers bind IPv6 loopback and
  the sidecar's connector reaches them there.

## Scope and honesty

This spike re-confirms containment codex already had, the netns and the
sensitive-home masking, and only adds the placeholder and injection framing on
top. The break-out battery is the interesting part. It actively attacks the box
and reports every result, including the ones that get out. Read
[`FINDING.md`](FINDING.md) for the verdict.
