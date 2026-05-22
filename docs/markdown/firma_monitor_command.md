# `firma monitor`

Tail the local audit stream produced by the sidecar audit sink (and,
optionally, the authority and sidecar component logs). Single command,
single stream, line-oriented (not a TUI). Per Firma CLI Unified Spec
v0.5 §3.5.

`firma monitor` is read-only. Multiple concurrent monitors against the
same state directory are safe.

## Quickstart

```bash
firma monitor                                    # tail audit, follow if TTY
firma monitor --only-deny                        # tail audit, deny only
firma monitor --agent codex                      # tail audit for agent codex
firma monitor --tail                             # force follow even when piped
firma monitor --json | jq .                      # raw JSON pass-through
firma monitor --source all --since 15m           # backfill all sources 15m
```

## Surface

```text
firma monitor [--config <stack.toml>]
              [--state-dir <dir>]
              [--source audit|authority|sidecar|all]
              [--decision allow|deny|passthrough]
              [--only-deny]
              [--action-class <class>]
              [--agent <agent_id>]
              [--since <duration|rfc3339>]
              [--format pretty|json]
              [--json]
              [--tail]
              [--no-follow]
```

## Flags

| Flag             | Default              | Description                                                             |
| ---------------- | -------------------- | ----------------------------------------------------------------------- |
| `--config`       | _unset_              | Stack config; `state_dir` is read from it when set.                     |
| `--state-dir`    | resolved (see below) | State dir override.                                                     |
| `--source`       | `audit`              | `audit`, `authority`, `sidecar`, or `all`.                              |
| `--decision`     | _unset_              | Audit filter: `allow`, `deny`, `passthrough`.                           |
| `--only-deny`    | _off_                | Shortcut for `--decision deny`. Conflicts with `--decision`.            |
| `--action-class` | _unset_              | Audit filter: exact match on the `action` field.                        |
| `--agent`        | _unset_              | Audit filter: exact match on the `agent_id` field.                      |
| `--since`        | _unset_              | Backfill window: `15m`, `2h`, `1d`, or an RFC3339 timestamp.            |
| `--format`       | `pretty`             | `pretty` (human) or `json` (byte-for-byte pass-through of audit lines). |
| `--json`         | _off_                | Shortcut for `--format json`. Conflicts with `--format`.                |
| `--tail`         | _off_                | Force follow even when stdout is piped. Conflicts with `--no-follow`.   |
| `--no-follow`    | _off_                | Read once and exit. Conflicts with `--tail`.                            |

## Auto-tail behavior

Default follow mode is decided per the table below. `--tail` and
`--no-follow` are explicit overrides.

| `--tail` | `--no-follow` | stdout is TTY | Follows? |
| -------- | ------------- | ------------- | -------- |
| set      | _off_         | any           | yes      |
| _off_    | set           | any           | no       |
| _off_    | _off_         | yes           | yes      |
| _off_    | _off_         | no            | no       |

This keeps interactive use ergonomic (`firma monitor` follows the live
stream) while preventing pipes and CI redirects from hanging
indefinitely.

## Output formats

### Pretty (default)

```text
2026-05-08T14:22:31Z  ALLOW    POST  api.github.com/repos/x/y/issues    class=github.issue.create     agent=demo-1
2026-05-08T14:22:33Z  DENY     POST  api.stripe.com/v1/charges          class=stripe.payment.create   agent=demo-1  reason=scope_mismatch
```

The HTTP method column is best-effort: it is extracted from the
`action` field when it has the `raw.http.<METHOD>` form (unclassified
passthrough or deny), otherwise rendered as `-`.

### JSON (`--format json` / `--json`)

Audit records are emitted byte-for-byte unchanged, one JSON object per
line followed by `\n`. This is suitable for piping into `jq` or any
streaming JSON consumer without re-parsing the monitor's own output.

Authority and sidecar lines are wrapped with a `{"source":"…","raw":…}`
envelope in JSON mode because they are unstructured stdout/stderr.

## Source resolution

The audit log lives at `<state_dir>/audit.jsonl`. The state dir is
resolved in this order:

1. `--state-dir` flag.
2. `FIRMA_STATE_DIR` environment variable.
3. `state_dir` field in `--config` (when set).
4. Platform default: `$XDG_RUNTIME_DIR/firma` on Unix (or
   `/tmp/firma-$UID`); `%LOCALAPPDATA%\firma\runtime` on Windows (or
   `%TEMP%\firma`).

If the sidecar is not running, monitor tails what is on disk and waits
for new lines.

## Exit codes

| Code | Meaning                                               |
| ---- | ----------------------------------------------------- |
| `0`  | Clean exit (EOF in `--no-follow` mode, or SIGINT).    |
| `2`  | Internal error (state-dir resolution, render, parse). |

`Ctrl-C` always exits with code 0.

## See also

- [`docs/markdown/firma_init_command.md`](firma_init_command.md) — `firma config`.
- [`docs/markdown/firma_sidecar_daemon_command.md`](firma_sidecar_daemon_command.md) — `firma sidecar {start,stop,status}`.
- [`docs/markdown/firma_action_class_registry.md`](firma_action_class_registry.md) — action class registry referenced by `--action-class`.
