# Release demo

This demo shows FIRMA doing the thing it is built for: letting an agent make an allowed request, blocking a disallowed one, and leaving an audit trail for both decisions.

The demo starts a local Authority, starts a local Sidecar, gives the demo agent a short-lived permission token, and then runs one of the demo drivers. You can run it with an LLM-backed Python agent, an interactive REPL, or a deterministic client.

## What you will see

In the happy path, the agent asks for weather data and the Sidecar allows the request. In the deny path, the agent tries to send data to `paste.rs` and the Sidecar blocks it.

The CI driver prints output like this:

```text
[allow] 200 OK path=/allow body={"ok":true,"path":"/allow"}
[deny] 403 Forbidden path=/deny body={"denied":true,"reason":"...","detail":"..."}
[ok] ALLOW + DENY round-trips matched expectation.
```

The LLM-backed hero driver prints labelled turns like this:

```text
[turn 1] tool=get_weather decision=ALLOW status=200
[turn 2] tool=exfiltrate_to_paste decision=DENY status=403
```

The LLM path is best-effort because models can choose different tool paths. The deterministic CI path is the one used as a stable gate.

## Prerequisites

All modes require a working Rust toolchain and `protoc`.

The CI mode does not need API keys. The hero and REPL modes also need Python
with `uv` and an `OPENAI_API_KEY` in `examples/demo/.env`.

## Run it

From the repository root:

```bash
make demo-ci
```

That mode does not need API keys. It builds the required binaries, starts the Authority and Sidecar, runs the Rust fixture client, and checks that both an ALLOW and DENY audit event were emitted.

To run the LLM-backed scripted demo:

```bash
cp examples/demo/.env.sample examples/demo/.env
# Add OPENAI_API_KEY to examples/demo/.env
make demo
```

To run the interactive Python agent REPL behind the same local stack:

```bash
make demo-repl
```

## Demo modes

| Mode | Command | What it runs | Requires API keys | Used in CI |
| --- | --- | --- | --- | --- |
| CI | `make demo-ci` | Deterministic Rust fixture client | no | yes |
| Hero | `make demo` | Scripted Python agent | yes | no |
| REPL | `make demo-repl` | Interactive Python agent | yes | no |

All three modes use the same local Authority and Sidecar configuration. The demo runner is `examples/demo/run.sh`.

## What the runner creates

The first run creates local runtime files under `examples/demo/`:

- `firma-authority.key` and `firma-authority.pub` for Authority token signing;
- `authority-ca.crt` and `authority-ca.key` for Authority transport TLS;
- `authority.crt` and `authority.key` for the Authority gRPC server cert/key;
- `audit.key` for signing audit events;
- `capability-demo-agent.toml` as the pre-issued permission token seed;
- `revocations.txt` as the local revocation file;
- `firma-ca/` for the Sidecar HTTPS interception CA;
- `logs/` for Authority, Sidecar, and fixture logs.

These files are generated locally and are not committed.

Transport note: the demo now defaults to `https://127.0.0.1:50051` for Sidecar
-> Authority streams. `examples/demo/run.sh` auto-runs
`firma authority init-tls --out-dir .` when TLS files are missing.

## Files in this example

```text
examples/demo/
├── run.sh              Starts the local Authority, Sidecar, and selected driver.
├── firma.toml          Unified config ([authority] + [sidecar.*]).
├── mapping-rules.toml  Request-to-action mappings used by the demo.
├── policies/           Cedar policies streamed by the Authority.
├── .env.sample         Environment template for LLM-backed modes.
└── .gitignore          Ignores generated keys, tokens, logs, and CA files.
```

## Troubleshooting

If an expected ALLOW returns `403`, check `examples/demo/logs/sidecar.log`. The most common causes are an expired or missing capability seed, a mismatched session ID, or a request that does not match the demo mapping.

If the Authority refuses to start after local experimentation, delete `examples/demo/firma-authority.key` and `examples/demo/firma-authority.pub`, then rerun the demo. The runner will regenerate them.

If the demo pauses for a long time in a debugger, the Sidecar can treat the policy bundle as stale. Increase `bundle_ttl_seconds` under `[sidecar.constraint_enforcement]` in `firma.toml` while debugging.

## Startup signal

When the Sidecar starts successfully, it ends with a `ready` log line. Automation should wait for that signal before sending traffic.
