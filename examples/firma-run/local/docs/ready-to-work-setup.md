# Ready-to-Work Setup (Codex + Claude)

This is the fastest path to a working local environment with strict governance:

- `default_protected = true`
- sidecar HTTP proxy + HTTPS MITM
- authority stream enabled
- session-bound capability token flow

Use this when onboarding a developer who needs a known-good setup quickly.

## Preconditions

- Repo root: `firma-oss`
- `.local/authority.toml` exists
- `cargo` available

## 1) Bootstrap local files

```bash
examples/firma-run/local/setup.sh
```

## 2) Pick your target agent

Codex:

```bash
cp examples/firma-run/local/assets/firma_sidecar.local.codex.example.toml .local/firma_sidecar.local.toml
cp examples/firma-run/local/assets/mapping-rules.codex.local.example.toml .local/mapping-rules.toml
export FIRMA_RUN_SESSION_ID=demo-session-codex
examples/firma-run/local/renew-capability.sh --session-id "$FIRMA_RUN_SESSION_ID" --output .local/capability-codex.toml
```

Claude:

```bash
cp examples/firma-run/local/assets/firma_sidecar.local.claude.example.toml .local/firma_sidecar.local.toml
cp examples/firma-run/local/assets/mapping-rules.claude.local.example.toml .local/mapping-rules.toml
export FIRMA_RUN_SESSION_ID=demo-session-claude
examples/firma-run/local/renew-capability.sh --session-id "$FIRMA_RUN_SESSION_ID" --output .local/capability-claude.toml
```

## 3) Start services (3 terminals)

Terminal A (authority):

```bash
cargo run -p firma-authority -- --config .local/authority.toml
```

Terminal B (sidecar):

```bash
cargo run -p firma-sidecar -- -c .local/firma_sidecar.local.toml
```

Terminal C (agent via `firma run`):

```bash
export FIRMA_RUN_REQUIRE_SESSION_ID=true
```

Codex:

```bash
cargo run -p firma-run -- run --profile codex -- codex
```

Claude:

```bash
cargo run -p firma-run -- run --profile claude-code -- claude
```

## 4) Expected signals

- Sidecar logs `ready`.
- Sidecar logs authority stream connected (not disabled).
- Agent starts and can call its control-plane endpoints without `UnclassifiedIntent`.

## Troubleshooting quick map

- `TokenExpired`:
  - Re-issue token with same `FIRMA_RUN_SESSION_ID`.
  - Restart sidecar if using `[capability_seed]`.

- `TokenInvalid`:
  - Session mismatch or wrong token file.
  - Ensure token was issued with the same session id as runtime.

- `UnclassifiedIntent`:
  - Add mapping rule for method/host/path.
  - With MITM enabled, add HTTP path mappings, not only CONNECT.

- `PolicyBundleStale`:
  - Ensure authority is running and `policy.authority_url` is set.

- MCP/JSON-RPC deserialize errors during startup:
  - Usually upstream unauthorized flow caused by missing classified routes or token/policy issues.
  - Check sidecar audit for `dispatch_status` and denies.

## Important model note

When the agent says "Searching the web", the tool may use provider-mediated paths.
That can produce external sources in output without direct shell egress to those domains.
For direct shell governance checks, validate with explicit `curl`/`wget` inside the sandboxed session.
