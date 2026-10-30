# Changelog

User-facing changes are listed first. Internal improvements are grouped at the end.

## [0.2.0-rc4](https://github.com/Firma-AI/openfirma/compare/v0.2.0-rc3...v0.2.0-rc4) - 2026-10-30

### Added

- **sidecar:** Deny traffic and stop once the Authority rejects the run
- **cli:** Default firma login to the hosted control plane

### Fixed

- **run:** Let Ctrl-C kill a stopped agent and close the review gaps

## [0.2.0-rc3](https://github.com/Firma-AI/openfirma/compare/v0.2.0-rc2...v0.2.0-rc3) - 2026-10-29

### Added

- **run:** **Breaking:** Derive agent capabilities from policy, not firma.toml
- **cli:** Resolve a Firma Team Agent with firma run --agent
- **cli:** Reserve and activate an execution with firma run --agent
- **executions:** Keep an execution alive while its Sidecar's stream ticks
- **agents:** Advertise the gRPC URI and the capability key at resolution
- **sidecar:** Authenticate with an execution's runtime credential
- **cli:** Run the command as the activated execution
- **cli:** Close the execution when firma run --agent ends
- **revocation:** **Breaking:** Send the unpurged set instead of one event per revocation
- **openfirma:** **Breaking:** Evaluate policies with Cedar 4.10
- **executions:** **Breaking:** Start an execution with one one-shot call
- **cli:** Print the next command after firma login
- **authority-ui:** Render the firma login return page on the server
- **runs:** **Breaking:** Name authorized worker starts runs
- **authority:** Preserve machine runtime provenance
- **sidecar:** Verify an https Authority against the platform roots when no CA is set
- **config:** Make the Authority CA optional for agent-remote
- **run:** Reach an https Authority from managed runs
- **sidecar:** Trust a list of Authority CAs and allow switching the platform store off
- **run:** Stop a running agent when the workspace ends its run

### Fixed

- **ci:** Preserve live-agent TLS failure diagnostics
- **revocation:** Gate readiness on a delivered set and floor the purge grace
- **deps:** Move the workspace ECDSA stack to crypto-bigint 0.7
- **installer:** Drop Homebrew and fix Rosetta and PATH-shadow failures

## [0.2.0-rc2](https://github.com/Firma-AI/openfirma/compare/v0.2.0-rc1...v0.2.0-rc2) - 2026-10-19

This release candidate inspects all agent HTTPS traffic by default, makes the
Authority the single source of action mappings, keeps CLI secret providers'
credentials outside the sandbox, and adds `firma login` for Firma Team.
Generated configuration is now portable between machines.

Several configuration contracts change in this release. Review the breaking
changes before upgrading an existing installation.

### Highlights

#### HTTPS interception for every host

The Sidecar now intercepts every host an agent reaches, so every request is
subject to request-level policy and audit, not only those to a curated list of
providers.

- `intercept_hosts` and `strict_hosts` default to every host. A host that
  cannot be intercepted is denied instead of being tunnelled uninspected.
- List hosts that use certificate pinning, upstream mTLS, or non-TLS tunnels in
  `bypass_hosts`, which now also accepts the underscore names common in
  internal DNS. `bypass_hosts = ["*"]` turns interception off.
- The `vscode` and `copilot` mapping templates now classify the requests
  inside every connection they open, so intercepting their hosts does not
  deny their own traffic.
- A strict host that refuses a non-TLS tunnel now records a deny audit event.

#### Action mappings come from the Authority

`[authority].mapping_rules_paths` is now the only place to configure action
mappings. The Authority publishes them together with policies and the schema as
one versioned snapshot, so a Sidecar always enforces a consistent set.

- The local Authority started by `firma run` publishes the mapping files
  selected with `firma config`. A Sidecar connected to a remote or Firma Team
  Authority receives that Authority's mappings.
- A Sidecar refuses to classify requests while its snapshot is not yet loaded
  or has expired. An invalid update keeps the previous snapshot without
  extending its lifetime.
- `/healthz` reports unhealthy while the enforced snapshot is past its TTL, and
  `firma sidecar status` shows the enforced version in a new `BUNDLE` column.
- The Authority reloads policies, mappings, and the schema when mounted
  configuration such as a Kubernetes `ConfigMap` changes.

#### Secret providers stay outside the sandbox

When a `firma run` profile configures CLI secret providers, such as `op`,
`vault`, `bws`, or `doppler`, the agent's calls to them are now executed by a
broker outside the sandbox. Provider credentials never enter the sandbox, and
their environment variables are removed from the agent's environment.

- Supported on the Linux bwrap backend and the macOS VZ guest backend.
- Install with the `curl | sh` installer. On macOS, `brew install
  Firma-AI/openfirma/firma` on its own does not yet include what the VZ backend
  needs, so VZ runs that configure CLI providers fail closed.
- New examples show complete custom CLI and HTTP secret integrations.

#### Log in to Firma Team

`firma login --control-plane-origin <url>` connects the CLI to a Firma Team
Workspace through browser approval, or with `--terminal-code` when the browser
cannot reach this machine.

- The connection is saved. On Linux and macOS the CLI stores a renewable
  credential in the operating system credential store and refreshes it as
  needed.
- `firma logout` revokes the credential on the Control Plane and removes the
  saved connection.
- On Linux bwrap, the saved login is hidden from sandboxed agents.

#### Portable configuration

`firma config` no longer writes machine-specific paths into `firma.toml`.

- Signing keys, the revocation list, TLS material, the audit log and its key,
  and the MITM CA default to the state directory. Each remains an accepted
  override.
- `firma run` derives the agent's workspace from the directory that contains
  `.firma/`, so a scaffolded profile no longer needs a workspace mount.

### Breaking changes

#### HTTPS interception

- Every host an agent reaches must trust the Sidecar CA. `firma run` configures
  this for the processes it starts; anything else needs the CA installed
  separately.
- Endpoints that cannot be intercepted are denied until they are listed in
  `bypass_hosts`.
- Re-running `firma config` removes `enabled`, `intercept_hosts`, and
  `strict_hosts` written by earlier versions, and reports what it removed. A
  hand-written `intercept_hosts` or `strict_hosts` list still replaces the
  default.
- `firma config` refuses to run while a selected mapping file on disk would
  deny intercepted traffic to one of its hosts. Regenerate it with `--force`.

#### Mapping configuration

- `[sidecar.mapping]` is rejected. Its error explains where to configure
  mappings instead.
- Every Sidecar now requires an Authority URL. Sidecars without an Authority
  endpoint are no longer supported.
- `firma config --mode agent-remote` writes no local mapping files and rejects
  `--mapping` and `--extra-hosts`.

#### Default paths and the state directory

These defaults changed for configurations that leave the keys unset:

| Key                         | Old default                                | New default                      |
| --------------------------- | ------------------------------------------ | -------------------------------- |
| `authority.key_file`        | `firma-authority.key` beside the config    | `<state_dir>/authority.key`      |
| `authority.revocation_file` | `revocations.txt` in the working directory | `<state_dir>/revocations.txt`    |
| `sidecar.ca.dir`            | `./firma-ca/` in the working directory     | `<state_dir>/generated-firma-ca` |

- A new `sidecar.ca.dir` means a new MITM CA. Set the key to keep the old
  directory, or re-import the new CA wherever the old one was trusted.
- A non-default state directory is no longer recorded in `firma.toml`. Pass it
  to every process through `FIRMA_STATE_DIR`.
- An Authority with no TLS configuration and no generated TLS material now
  fails to start instead of serving plaintext. Pass `firma authority --no-tls`
  to choose plaintext explicitly.
- `mtls_client_ca_key_path` now requires `mtls_client_ca_cert_path`.
- A run started from a project subdirectory now mounts the project root rather
  than the current directory. Tools that read the workspace from `firma.toml`
  should use the directory that contains `.firma/`.

#### Removed Sidecar settings

- `[sidecar].mode`, `firma run --monitor`, and `FIRMA_ALLOW_MONITOR_MODE` are
  removed. The Sidecar always enforces; permit calls in policy instead.
- `[sidecar.capability_validation].clock_skew_tolerance` is removed. Capability
  expiry is checked strictly against the Sidecar clock.
- `[sidecar.tenancy]` is removed.

Configurations generated by `0.2.0-rc1` contain `mode = "enforce"` and
`clock_skew_tolerance = "0s"`. Delete both lines; the error names each one.

#### Audit sinks

- The `grpc` sink now requires `buffer_path`. While the audit service is
  unreachable it buffers events there and replays them in order on reconnect,
  clearing them only after the service acknowledges them.
- The `wal` sink now syncs each event to `wal_path` before sending it and keeps
  it until the collector durably acknowledges it. A full journal fails the sink
  instead of dropping events.
- If the audit buffer cannot be written, the Sidecar shuts down rather than
  keep enforcing without an audit trail.

#### Capabilities and client identities

- `firma run --capability-file` and Sidecar capability seeds accept only the
  canonical seed TOML written by `firma authority issue`. Re-issue capabilities
  stored as a bare token.
- Sidecar capability seeds must resolve inside `<state_dir>/capabilities/`.
- The Authority mTLS allow-list accepts only `[[clients]]` entries with an
  `identity`. Rename `[[authorized]]` entries.

### Reliability and compatibility

- `firma run` no longer leaks a thread, two sockets, and an upstream connection
  for every finished proxied connection.
- `firma run` keeps signing audit events with the shared key, regenerates its
  local Authority's TLS material after the runtime directory is cleared, and
  treats `HTTPS://` like `https://`.
- New `[sidecar.audit]` settings `replay_ack_timeout` and `wal_request_timeout`
  bound how long the Sidecar waits on an audit collector.
- A chunked request no longer consumes the next pipelined request as its
  trailer.
- `firma config` recognizes mapping paths by the file they name, so a respelled
  path is not duplicated or kept after its mapping is deselected.
- `firma doctor` checks the Authority against the state directory it was given.
- An empty mapping file reports `mapping file "<name>" is empty`.
- The installer replaces an existing installation atomically and restores it if
  the update fails.
- Building from source requires Rust 1.99.

### Security

- Sensitive query values are masked in audit records even when the parameter
  name is percent-encoded.
- The per-run audit signing key is generated from the operating system's
  random source and written with private file permissions.

### Documentation

Updated the configuration, mapping, audit, and upgrade guidance for
Authority-owned mappings, default interception, and state-directory defaults.

## [0.2.0-rc1](https://github.com/Firma-AI/openfirma/compare/v0.1.6...v0.2.0-rc1) - 2026-09-12

This release candidate adds managed secret injection, expands policy enforcement,
and substantially improves the reliability of managed OpenFirma processes.

Because this release tightens several configuration contracts, review the
breaking changes before upgrading an existing installation.

### Highlights

#### Managed secrets

OpenFirma can now keep credentials outside the agent sandbox and inject them
only when an authorized request is executed.

- Added secret-provider configuration and a built-in Doppler provider.
- Added brokered secret transport between `firma run` and the Sidecar.
- Added request header and body rewriting for credential injection.
- Credentials supplied by an agent are replaced with the configured secret
  rather than forwarded.
- Broker failures, malformed responses, and ambiguous outcomes now fail closed.

#### More expressive policies

Cedar policies can now inspect the target resource's `host` and `path`. This
allows policies to restrict requests to particular services or endpoints
without relying only on action classifications.

Existing policies that reference `resource.id` also now evaluate against a
populated resource entity.

#### Governed Composio execution

The Sidecar can classify and govern Composio tool execution, including hosted
MCP requests and account operations for integrations such as Notion and Slack.

#### Policy workflow improvements

The terminal interface now provides contextual overlays and can open the
selected policy source directly in your editor.

### Breaking changes

#### Configuration values

- Durations now use explicit units such as `"500ms"`, `"30s"`, or `"1h"`.
- Byte quantities now use values such as `"4 MiB"`.
- Authority TTLs must be greater than zero.
- Configuration paths are resolved relative to the containing `firma.toml`
  and canonicalized where required.
- Executable allowlists must reference existing regular files.
- Obsolete Authority, Sidecar, Run, logging, timeout, and constraint fields are
  now rejected rather than ignored.

#### Run profile resolution

Run profiles now merge deterministically in this order:

1. Built-in profile
2. `[run.defaults]`
3. Selected profile
4. Command-line options

Explicit `false` and empty collections now override inherited values. Invalid
legacy Run configuration forms are rejected.

#### Configuration discovery

`doctor`, `control`, and `monitor` now use the canonical configuration lookup:

1. Explicit `--config`
2. `FIRMA_CONFIG`
3. The nearest `.firma/firma.toml`

`FIRMA_STACK_CONFIG` is no longer recognized.

#### Sidecar templates

Autostart Sidecar templates must be unified `firma.toml` documents containing
a `[sidecar]` section. Flat templates, unknown fields, missing explicit
templates, and unreadable templates now fail closed.

#### Identifiers

Generated audit event, approval token, and session identifiers now use
validated TypeIDs:

- `aevt_…` for audit events
- `atok_…` for approval tokens
- `ses_…` for generated sessions

Consumers that parse these generated identifiers as plain UUIDs must be
updated.

### Reliability and compatibility

- Detached Authority and Sidecar processes now retain ownership correctly
  during startup, shutdown, handoff, and forced termination.
- Concurrent and stale runtime generations are isolated and cleaned up safely.
- Corrupt runtime state is rejected instead of being reused.
- Components use kernel-assigned endpoints and publish readiness only after
  they are ready to accept traffic.
- Sidecar audit events are flushed before WAL replay, preventing the newest
  event from being lost during reconnect or compaction.
- DNS stub port allocation is more reliable under contention.
- IPv6 hosts now receive the same default-port normalization as IPv4 hosts.
- The VS Code profile recognizes the required GitHub Copilot endpoints.

### Security

- The Linux `bwrap` sandbox can no longer read OpenFirma configuration and
  control-plane runtime assets unless they are explicitly mounted.
- Secret injection and Composio execution paths now apply stricter lifecycle,
  authorization, and failure handling.
- Updated `h2` to address an upstream security advisory.

### Documentation

Expanded guidance for process lifecycle ownership, black-box testing,
orchestration, and agent-assisted development.

## [0.1.6](https://github.com/Firma-AI/openfirma/compare/v0.1.5...v0.1.6) - 2026-07-30

<details>
<summary>Internal Improvements</summary>

- Improve the release process ([#365](https://github.com/Firma-AI/openfirma/pull/365))

</details>
