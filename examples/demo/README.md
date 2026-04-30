# Firma OSS — Release Demo

Single-command end-to-end demo of the Firma sidecar plus the Mini
Authority. `make demo` boots both binaries, pre-issues a capability
seed, and drives ALLOW + DENY round-trips against either the LLM-backed
Python agent or the deterministic Rust CI client.

## Prerequisites

- Rust toolchain matching `rust-toolchain.toml`.
- `protoc` (for `firma-proto`).
- For the hero (`make demo`) and repl (`make demo-repl`) modes: a
  working `uv`/Python and `OPENAI_API_KEY`. CI mode needs neither.

## Layout

```
examples/demo/
├── README.md                     # this file
├── sidecar.toml                  # canonical SidecarConfig
├── authority.toml                # mini-authority config
├── mapping-rules.toml            # protected (method, host, path) tuples
├── policies/                     # Cedar bundle the authority streams
│   ├── default.cedar             # base permit
│   ├── example-deny.cedar        # forbid POST paste.rs (hero deny)
│   └── fixture-deny.cedar        # forbid POST 127.0.0.1:9100/deny (CI deny)
├── .env.sample                   # OPENAI_API_KEY etc. (hero only)
├── .gitignore                    # bootstrapped artifacts (keys, seed, logs)
├── audit.key                     # generated: ECDSA P-256 audit signing key
├── firma-authority.key           # generated: PASETO v4 signing key (private)
├── firma-authority.pub           # generated: PASETO v4 public key
├── revocations.txt               # generated: empty by default
├── capability-demo-agent.toml    # generated: pre-issued capability seed
└── logs/                         # generated: authority.log, sidecar.log, fixture.log
```

The seven `generated:` artifacts are produced on first run by
`scripts/demo.sh` and `make demo-ci`. None of them are committed.

## Modes

The orchestrator dispatches three modes that share the same authority
+ sidecar boot path. Both LLM modes pre-issue a single capability via
`firma-authority issue` on first run; the resulting seed is written to
`capability-demo-agent.toml` and consumed by the sidecar's
`[capability_seed]` section.

| Mode | Trigger          | Driver                                | LLM | API keys | CI gate |
|------|------------------|---------------------------------------|-----|----------|---------|
| Hero | `make demo`      | `agents_sdk_py/agent/scripted.py`     | yes | yes      | no      |
| Repl | `make demo-repl` | `agents_sdk_py/agent/main.py` (REPL)  | yes | yes      | no      |
| CI   | `make demo-ci`   | `firma-demo-fixture-client`           | no  | no       | yes     |

### `make demo-ci` expected output

```text
[allow] 200 OK path=/allow body={"ok":true,"path":"/allow"}
[deny] 403 Forbidden path=/deny body={"denied":true,"reason":"...","detail":"..."}
[ok] ALLOW + DENY round-trips matched expectation.
```

The `demo-e2e` GitHub Actions job greps `examples/demo/logs/sidecar.log`
for exactly one ALLOW and one DENY audit event after the run finishes;
both must be present for the job to pass.

### `make demo` expected output

The scripted Python driver prints two labelled transcripts:

```text
[turn 1] tool=get_weather decision=ALLOW status=200
[turn 2] tool=exfiltrate_to_paste decision=DENY status=403
```

LLMs choose tool paths nondeterministically, so this mode is
documented as best-effort and is never gated by CI.

## Troubleshooting

- **ALLOW returns 403** — the sidecar's `[capability_seed].paths` does
  not match the seed file the orchestrator just produced, or the
  request was missing the `x-firma-session-id: demo-session` header.
  Check `examples/demo/logs/sidecar.log` for the exact denial reason.
- **Authority refuses to start** — delete `firma-authority.key` and
  re-run; the orchestrator regenerates it with the correct format.
- **Stale Cedar bundle** — increase `[constraint_enforcement]
  bundle_ttl_seconds` if the demo is paused at a breakpoint long
  enough for the bundle to age out.

## Standalone startup contract

On every successful start the sidecar emits seven INFO lines in order
(see `docs/cli.md`):

```text
config loaded             path="…"
mapping table loaded      rules=N
policy bundle loaded      version="…" policies=N
authority stream connected endpoint="…"
connector registry built  hosts=N default_timeout_ms=T
interceptor listening     addr="…"
ready
```

Operators automating Firma should wait for `ready` before sending
traffic.
