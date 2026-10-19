# Codex + Claude Local Setup (Strict Mode)

This guide provides ready-to-use local setups for `firma run` with:

- `--profile codex`
- `--profile claude-code`

Both tracks assume:

- protected Authority mapping snapshots (unmatched traffic is denied)
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

This is required when `sidecar.interceptor.https_mitm.enabled = true`: the
Sidecar sees the decrypted inner requests, and the Authority's snapshot denies
any request that no rule matches.

Recommended local destinations:

- `.local/firma.toml`
- `.local/mapping-rules.toml`

## 1) Bootstrap local artifacts

```bash
examples/firma-run/local/setup.sh
```

This creates `.local/` scaffolding, including audit key material.

## 2) Choose an agent track (Codex or Claude)

Copy one config sample and one mapping sample into `.local/`:

```bash
# Codex track
cp examples/firma-run/local/assets/firma.local.codex.example.toml .local/firma.toml
cp examples/firma-run/local/assets/mapping-rules.codex.local.example.toml .local/mapping-rules.toml

# Claude track
# cp examples/firma-run/local/assets/firma.local.claude.example.toml .local/firma.toml
# cp examples/firma-run/local/assets/mapping-rules.claude.local.example.toml .local/mapping-rules.toml
```

## 3) Complete the local Authority configuration

`firma config` adds the Authority listener, generates the Authority key and
TLS material, and keeps the sample's `[authority].mapping_rules_paths`:

```bash
cargo run -p firma -- config --yes --mode agent-local --profile codex \
  --agent-id agt_01j0000000e008000000000001 --output-dir .local
```

Use `--profile claude-code` for the Claude track.

## 4) Start the Authority

```bash
cargo run -p firma -- authority --config .local/firma.toml
```

Keep this running in its own terminal. Every Sidecar requires it: the
Authority publishes the policy and mapping snapshot.

## 5) Run the agent through `firma run`

`firma run` starts a per-session Sidecar and mints a capability automatically
on each session start. No manual token issuance is required.

Codex:

```bash
export FIRMA_RUN_REQUIRE_SESSION_ID=true
export FIRMA_RUN_SESSION_ID=<stable-value>
cargo run -p firma -- run --config .local/firma.toml --profile codex \
  --authority https://127.0.0.1:50051 --sidecar local -- codex
```

Claude:

```bash
export FIRMA_RUN_REQUIRE_SESSION_ID=true
export FIRMA_RUN_SESSION_ID=<stable-value>
cargo run -p firma -- run --config .local/firma.toml --profile claude-code \
  --authority https://127.0.0.1:50051 --sidecar local -- claude
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
- The Authority watches its mapping files and publishes the updated snapshot;
  running Sidecars apply it without a restart.

## Validation checks

Codex local smoke:

```bash
examples/firma-run/e2e/run.sh --profile codex
```

Claude local acceptance (Linux-first):

```bash
examples/firma-run/e2e/run.sh --claude-acceptance
```
