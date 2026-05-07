# Codex + Claude Local Setup (Strict Mode)

This guide provides ready-to-use local setups for `firma run` with:

- `--profile codex`
- `--profile claude-code`

Both tracks assume:

- `default_protected = true`
- sidecar in `http_proxy` mode
- capability token tied to a stable `session_id`
- authority stream enabled (fail-closed posture)

## Session and token model (important)

In strict mode, capability validation is session-aware:

- `firma run` sends `x-firma-session-id` on governed traffic.
- Sidecar Stage 1 selects a capability token whose claims match that
  `session_id`.
- If session ids do not match, enforcement denies with `TokenInvalid`.

### Why we set `FIRMA_RUN_SESSION_ID`

`firma run` can generate a new session id every run. That is fine for
stateless scenarios, but it breaks pre-issued seed-token workflows where
the token is tied to a fixed `session_id`.

For stable local dev, set:

- `FIRMA_RUN_SESSION_ID=<stable-value>`
- `FIRMA_RUN_REQUIRE_SESSION_ID=true`

This guarantees deterministic matching between runtime attribution and seeded
capability claims.

### Token lifecycle

1. Issue token for the exact session id:
   - `examples/firma-run/local/renew-capability.sh --session-id "$FIRMA_RUN_SESSION_ID" ...`
2. Sidecar loads token via `[capability_seed].paths` at startup.
3. Requests are enforced against that token until expiry.
4. On expiry, sidecar denies with `TokenExpired`.
5. Re-issue token for the same session id and restart sidecar.

### Common failure modes

- `TokenInvalid`:
  - session mismatch, wrong agent id, or missing scope/action coverage.
- `TokenExpired`:
  - token TTL elapsed; renew and reload.
- `PolicyBundleStale`:
  - authority stream/policy readiness not satisfied in fail-closed mode.

## Files to copy

Codex:

- `examples/firma-run/local/assets/firma_sidecar.local.codex.example.toml`
- `examples/firma-run/local/assets/mapping-rules.codex.local.example.toml`

Claude:

- `examples/firma-run/local/assets/firma_sidecar.local.claude.example.toml`
- `examples/firma-run/local/assets/mapping-rules.claude.local.example.toml`

Note: the Claude mapping sample includes both:

- `CONNECT` destination mappings, and
- MITM inner HTTP path mappings (for example `/v1/*`, `/api/*`)

This is required when `https_mitm.enabled = true` and `default_protected = true`.

Recommended local destinations:

- `.local/firma_sidecar.local.toml`
- `.local/mapping-rules.toml`

## 1) Bootstrap local artifacts

```bash
examples/firma-run/local/setup.sh
```

This creates `.local/` scaffolding, including audit key material.

## 2) Start authority (required for fail-closed stream mode)

```bash
cargo run -p firma-authority -- --config .local/authority.toml
```

Keep this running in its own terminal.

## 3) Choose an agent track (Codex or Claude)

Copy one sidecar sample and one mapping sample into `.local/`:

```bash
# Codex track
cp examples/firma-run/local/assets/firma_sidecar.local.codex.example.toml .local/firma_sidecar.local.toml
cp examples/firma-run/local/assets/mapping-rules.codex.local.example.toml .local/mapping-rules.toml

# Claude track
# cp examples/firma-run/local/assets/firma_sidecar.local.claude.example.toml .local/firma_sidecar.local.toml
# cp examples/firma-run/local/assets/mapping-rules.claude.local.example.toml .local/mapping-rules.toml
```

## 4) Set stable session id and issue capability token

Codex:

```bash
export FIRMA_RUN_SESSION_ID=demo-session-codex
examples/firma-run/local/renew-capability.sh \
  --session-id "$FIRMA_RUN_SESSION_ID" \
  --output .local/capability-codex.toml
```

Claude:

```bash
export FIRMA_RUN_SESSION_ID=demo-session-claude
examples/firma-run/local/renew-capability.sh \
  --session-id "$FIRMA_RUN_SESSION_ID" \
  --output .local/capability-claude.toml
```

## 5) Start sidecar

```bash
cargo run -p firma-sidecar -- -c .local/firma_sidecar.local.toml
```

Verify startup includes:

- `authority stream connected endpoint=...` (not disabled)
- `ready`

## 6) Run the agent through `firma run`

Codex:

```bash
export FIRMA_RUN_REQUIRE_SESSION_ID=true
cargo run -p firma-run -- run --profile codex -- codex
```

Claude:

```bash
export FIRMA_RUN_REQUIRE_SESSION_ID=true
cargo run -p firma-run -- run --profile claude-code -- claude
```

## Expected behavior

- Shell-originated outbound traffic is mediated through sidecar path.
- Unknown/unmapped protected requests deny as `UnclassifiedIntent`.
- Expired capability denies as `TokenExpired`.
- Authority/policy availability failures deny as `PolicyBundleStale`.

## Fast recovery playbook

Capability expired:

```bash
examples/firma-run/local/renew-capability.sh --session-id "$FIRMA_RUN_SESSION_ID" --output .local/capability-codex.toml
# or .local/capability-claude.toml
```

Then restart sidecar (seed files are loaded at startup).

Unclassified endpoint:

- Add a specific mapping rule in `.local/mapping-rules.toml` for method/host/path.
- Restart sidecar.

## Validation checks

Codex local smoke:

```bash
examples/firma-run/e2e/run.sh --profile codex
```

Claude local acceptance (Linux-first):

```bash
examples/firma-run/e2e/run.sh --claude-acceptance
```
