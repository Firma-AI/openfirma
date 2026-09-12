# Changelog

User-facing changes are listed first. Internal improvements are grouped at the end.

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
