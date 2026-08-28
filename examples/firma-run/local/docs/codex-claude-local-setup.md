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

### Optional stable session identity

`firma run` generates a new session id by default. Set a stable identity when
you need audit correlation across repeated local invocations:

For stable local dev, set:

- `FIRMA_RUN_SESSION_ID=<stable-value>`
- `FIRMA_RUN_REQUIRE_SESSION_ID=true`

The same value is used for runtime attribution and automatic capability
issuance.

### Token lifecycle

`firma run` mints a per-session capability live via
the Authority's `IssueCapability` gRPC call and writes it to
`$XDG_RUNTIME_DIR/firma/capabilities/<sandbox_id>.toml`. The autostarted sidecar
loads it at startup and installs verified refreshes automatically.

### Common failure modes

- `TokenInvalid`:
  - session mismatch, wrong agent id, or missing scope/action coverage.
- `TokenExpired`:
  - token TTL elapsed; renew and reload.
- `PolicyBundleStale`:
  - authority stream/policy readiness not satisfied in fail-closed mode.

## Files to copy

Codex:

- `examples/firma-run/local/assets/firma.local.codex.example.toml`
- `examples/firma-run/local/assets/mapping-rules.codex.local.example.toml`

Claude:

- `examples/firma-run/local/assets/firma.local.claude.example.toml`
- `examples/firma-run/local/assets/mapping-rules.claude.local.example.toml`

Note: the Claude mapping sample includes both:

- `CONNECT` destination mappings, and
- MITM inner HTTP path mappings (for example `/v1/*`, `/api/*`)

This is required when `sidecar.interceptor.https_mitm.enabled = true` and
`sidecar.mapping.default_protected = true`.

Recommended local destinations:

- `.local/firma.toml`
- `.local/mapping-rules.toml`

## 1) Bootstrap local artifacts

```bash
examples/firma-run/local/setup.sh
```

This creates `.local/` scaffolding, including audit key material.

## 2) Start authority (required for fail-closed stream mode)

```bash
cargo run -p firma -- authority --config .local/firma.toml
```

Keep this running in its own terminal.

## 3) Choose an agent track (Codex or Claude)

Copy one sidecar sample and one mapping sample into `.local/`:

```bash
# Codex track
cp examples/firma-run/local/assets/firma.local.codex.example.toml .local/firma.toml
cp examples/firma-run/local/assets/mapping-rules.codex.local.example.toml .local/mapping-rules.toml

# Claude track
# cp examples/firma-run/local/assets/firma.local.claude.example.toml .local/firma.toml
# cp examples/firma-run/local/assets/mapping-rules.claude.local.example.toml .local/mapping-rules.toml
```

## 4) Run the agent (automatic capability mint)

`firma run` mints a capability automatically on each session start. No manual
token issuance is required.

## 5) Start sidecar

```bash
cargo run -p firma -- sidecar -c .local/firma.toml
```

Verify startup includes:

- `authority stream connected endpoint=...` (not disabled)
- `ready`

## 6) Run the agent through `firma run`

Codex:

```bash
export FIRMA_RUN_REQUIRE_SESSION_ID=true
cargo run -p firma -- run --profile codex -- codex
```

Claude:

```bash
export FIRMA_RUN_REQUIRE_SESSION_ID=true
cargo run -p firma -- run --profile claude-code -- claude
```

## Expected behavior

- Shell-originated outbound traffic is mediated through sidecar path.
- Unknown/unmapped protected requests deny as `UnclassifiedIntent`.
- Expired capability denies as `TokenExpired`.
- Authority/policy availability failures deny as `PolicyBundleStale`.

## Fast recovery playbook

Capability expired:

- Check the Authority connection and `firma run` refresh logs.
- Start a new `firma run` session after restoring Authority availability.

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
