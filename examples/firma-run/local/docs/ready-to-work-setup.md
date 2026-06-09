# Ready-to-Work Setup (Codex + Claude)

This is the fastest path to a working local environment with strict governance:

- `default_protected = true`
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
no manual token issuance is needed for the primary flow.

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

> **Legacy operator path (deprecated):** If you need a pre-provisioned seed
> token (fixed session id, non-autostart sidecar), set
> `FIRMA_RUN_SESSION_ID` and run `renew-capability.sh` before starting
> the sidecar. See `codex-claude-local-setup.md` for that flow.

## 3) Start services (3 terminals)

Terminal A (authority):

```bash
cargo run -p firma -- authority --config .local/firma.toml
```

Terminal B (sidecar):

```bash
cargo run -p firma -- sidecar -c .local/firma.toml
```

Terminal C (agent via `firma run`):

```bash
export FIRMA_RUN_REQUIRE_SESSION_ID=true
```

Codex:

```bash
cargo run -p firma -- run --profile codex -- codex
```

Claude:

```bash
cargo run -p firma -- run --profile claude-code -- claude
```

## 4) Expected signals

- Sidecar logs `ready`.
- Sidecar logs authority stream connected (not disabled).
- Agent starts and can call its control-plane endpoints without `UnclassifiedIntent`.

## Troubleshooting quick map

- `TokenExpired`:
  - Automatic path: start a new `firma run` session (capability is minted fresh each run).
  - Legacy `[capability_seed]` path: re-issue token with same `FIRMA_RUN_SESSION_ID` and
    restart sidecar.

- `TokenInvalid`:
  - Session mismatch or wrong token file.
  - Ensure token was issued with the same session id as runtime.

- `UnclassifiedIntent`:
  - Add mapping rule for method/host/path.
  - With MITM enabled, add HTTP path mappings, not only CONNECT.

- `PolicyBundleStale`:
  - Ensure authority is running and `authority.url` is set.

- MCP/JSON-RPC deserialize errors during startup:
  - Usually upstream unauthorized flow caused by missing classified routes or token/policy issues.
  - Check sidecar audit for `dispatch_status` and denies.

## Important model note

When the agent says "Searching the web", the tool may use provider-mediated paths.
That can produce external sources in output without direct shell egress to those domains.
For direct shell governance checks, validate with explicit `curl`/`wget` inside the sandboxed session.
