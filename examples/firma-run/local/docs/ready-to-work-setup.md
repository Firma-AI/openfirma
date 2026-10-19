# Ready-to-Work Setup (Codex + Claude)

This is the fastest path to a working local environment with strict governance:

- protected Authority mapping snapshots (unmatched traffic is denied)
- sidecar HTTP proxy + HTTPS MITM
- authority stream enabled
- session-bound capability token flow

Use this when onboarding a developer who needs a known-good setup quickly.

## Preconditions

- Repo root: `openfirma`
- `.local/firma.toml` exists
- `cargo` available

## 1) Bootstrap local files

```bash
examples/firma-run/local/setup.sh
```

## 2) Pick your target agent

Copy the config for your agent. `firma run` mints a capability automatically —
no manual token issuance is needed.

Codex:

```bash
cp examples/firma-run/local/assets/firma.local.codex.example.toml .local/firma.toml
cp examples/firma-run/local/assets/mapping-rules.codex.local.example.toml .local/mapping-rules.toml
```

Claude:

```bash
cp examples/firma-run/local/assets/firma.local.claude.example.toml .local/firma.toml
cp examples/firma-run/local/assets/mapping-rules.claude.local.example.toml .local/mapping-rules.toml
```

## 3) Complete the local Authority configuration

```bash
cargo run -p firma -- config --yes --mode agent-local --profile codex \
  --agent-id agt_01j0000000e008000000000001 --output-dir .local
```

Use `--profile claude-code` for Claude. `firma config` keeps the copied
`[authority].mapping_rules_paths` and generates the Authority key and TLS
material.

## 4) Start services (2 terminals)

Terminal A (authority):

```bash
cargo run -p firma -- authority --config .local/firma.toml
```

Terminal B (agent via `firma run` with a per-session Sidecar):

```bash
export FIRMA_RUN_REQUIRE_SESSION_ID=true
export FIRMA_RUN_SESSION_ID=<stable-value>
```

Codex:

```bash
cargo run -p firma -- run --config .local/firma.toml --profile codex \
  --authority https://127.0.0.1:50051 --sidecar local -- codex
```

Claude:

```bash
cargo run -p firma -- run --config .local/firma.toml --profile claude-code \
  --authority https://127.0.0.1:50051 --sidecar local -- claude
```

## 5) Expected signals

- Sidecar logs `authority stream connected endpoint=…` and
  `policy bundle loaded version=…`, then `ready`.
- Agent starts and can call its control-plane endpoints without `UnclassifiedIntent`.

## Troubleshooting quick map

- `TokenExpired`:
  - Check the Authority connection and `firma run` refresh logs.
  - Start a new `firma run` session after restoring Authority availability.

- `TokenInvalid`:
  - Session mismatch or wrong capability seed.
  - Ensure token was issued with the same session id as runtime.

- `UnclassifiedIntent`:
  - Add mapping rule for method/host/path.
  - With MITM enabled, add HTTP path mappings, not only CONNECT.

- `PolicyBundleStale`:
  - Ensure Authority is running and `[sidecar.authority].url` is set.

- MCP/JSON-RPC deserialize errors during startup:
  - Usually upstream unauthorized flow caused by missing classified routes or token/policy issues.
  - Check sidecar audit for `dispatch_status` and denies.

## Important model note

When the agent says "Searching the web", the tool may use provider-mediated paths.
That can produce external sources in output without direct shell egress to those domains.
For direct shell governance checks, validate with explicit `curl`/`wget` inside the sandboxed session.
