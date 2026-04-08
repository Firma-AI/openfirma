---
id: 005-config-and-startup
unit: 001-proxy-core
intent: 006-sidecar-proxy-enforcement
status: draft
priority: must
created: 2026-04-05T12:00:00Z
assigned_bolt: null
implemented: false
---

# Story: 005-config-and-startup

## User Story

**As an** operator
**I want** to configure the Sidecar via a TOML file with CLI overrides
**So that** I can manage settings declaratively with environment-specific overrides and be confident the Sidecar will not start in an invalid state

## Acceptance Criteria

- [ ] **Given** a valid TOML configuration file, **When** the Sidecar starts, **Then** all settings are loaded: listen address, policy directory, authority URL, CA directory, log level, drain timeout, and credential mappings
- [ ] **Given** a TOML configuration file and CLI arguments, **When** both specify the same setting (e.g., `--listen-addr`), **Then** the CLI argument takes precedence over the TOML value
- [ ] **Given** CLI arguments for common options, **When** the Sidecar starts, **Then** the following are supported: `--config` (path to TOML), `--listen-addr`, `--policy-dir`, `--authority-url`, `--log-level`, `--ca-dir`
- [ ] **Given** an invalid TOML configuration file (syntax error, missing required field, invalid value), **When** the Sidecar attempts to start, **Then** it fails fast with a clear error message identifying the specific problem and exits with a non-zero status code
- [ ] **Given** a valid configuration but a malformed policy file in the policy directory, **When** the Sidecar attempts to start, **Then** it fails fast and does not start with partial policies; the error message identifies the malformed file
- [ ] **Given** no configuration file and no CLI arguments, **When** the Sidecar starts, **Then** it uses sensible defaults: listen on `0.0.0.0:8080`, look for policies in `./policies/`, log level `info`, drain timeout `30s`

## Technical Notes

- Use the `toml` crate for TOML parsing and `clap` for CLI argument parsing with derive macros
- Configuration struct hierarchy example:
  ```toml
  [proxy]
  listen_addr = "0.0.0.0:8080"
  drain_timeout_secs = 30

  [policy]
  dir = "./policies/"
  # authority_url = "https://authority.example.com"  # optional; enables gRPC mode

  [ca]
  dir = "./firma-ca/"

  [log]
  level = "info"  # trace, debug, info, warn, error

  [credentials.openai]
  target_host = "api.openai.com"
  header = "Authorization"
  value_from_env = "OPENAI_API_KEY"
  prefix = "Bearer "
  ```
- Config resolution order: defaults -> TOML file -> CLI arguments (CLI wins)
- Fail-fast validation at startup should check:
  - Required directories exist and are readable (policy dir, CA dir)
  - Listen address is a valid socket address
  - Log level is a recognized value
  - If `authority_url` is set, it is a valid URL
  - All `.cedar` files in the policy directory parse successfully (delegate to policy source module)
- The configuration struct should be shared across the codebase (passed as `Arc<SidecarConfig>` or similar)
- Consider supporting environment variable interpolation in the TOML file (e.g., `value_from_env`) for credential configuration

## Dependencies

### Requires

- None (configuration is foundational; can be implemented first)

### Enables

- 001-http-proxy-listener (listen address comes from config)
- 003-ca-keypair-management (CA directory comes from config)
- 006-health-readiness-shutdown (drain timeout comes from config)
- All other units (policy dir, authority URL, credential mappings, log level)

## Edge Cases

| Scenario | Expected Behavior |
| -------- | ----------------- |
| Config file path specified but file does not exist | Fail-fast with clear error: "Config file not found: {path}" |
| Config file is empty | Use defaults for all settings (empty TOML is valid) |
| Config file has unknown keys | Ignore unknown keys with a warning log (forward-compatible) |
| Policy directory is empty (no `.cedar` files) | Fail-fast; a Sidecar with no policies would deny everything, which is valid fail-closed behavior, but an empty policy dir likely indicates misconfiguration |
| Listen port already in use | Fail-fast with OS-level "address already in use" error |
| CLI argument has invalid value (e.g., `--listen-addr not-an-address`) | Fail-fast with clap validation error before any initialization |
| TOML file has valid syntax but semantically invalid values (e.g., negative drain timeout) | Fail-fast with clear validation error identifying the field and constraint |
| Very large policy directory (hundreds of `.cedar` files) | All files loaded; warn if startup takes longer than expected |

## Out of Scope

- Hot-reloading of TOML configuration at runtime (restart required for config changes)
- Environment variable substitution beyond `value_from_env` for credentials
- Remote configuration sources (e.g., Consul, etcd)
- Configuration encryption or secret management (credentials in config are plaintext; operator secures the file)
