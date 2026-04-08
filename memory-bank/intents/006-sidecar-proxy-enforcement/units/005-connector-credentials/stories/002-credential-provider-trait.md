---
id: 002-credential-provider-trait
unit: 005-connector-credentials
intent: 006-sidecar-proxy-enforcement
status: draft
priority: must
created: 2026-04-05T12:00:00Z
assigned_bolt: null
implemented: false
---

# Story: 002-credential-provider-trait

## User Story

**As an** operator
**I want** to configure per-target credentials in a mapping table so that the Sidecar can inject authentication without the agent handling secrets
**So that** target-system secrets are managed centrally and never exposed to agent code

## Acceptance Criteria

- [ ] **Given** the Sidecar codebase, **When** a developer implements credential resolution, **Then** a `CredentialProvider` trait is available with an async `resolve(target: &str) -> Result<Credentials, CredentialError>` method for extensibility
- [ ] **Given** V1 configuration, **When** the Sidecar starts, **Then** a config-based `CredentialProvider` implementation reads per-target credential mappings from the TOML config (target host -> header name + value source)
- [ ] **Given** a credential mapping with `source = "env"` and a variable name, **When** the provider resolves credentials for that target, **Then** the credential value is read from the specified environment variable at resolution time
- [ ] **Given** a credential mapping with `source = "config"` and an inline value, **When** the provider resolves credentials for that target, **Then** the credential value is read from the configuration file
- [ ] **Given** a credential mapping with `injection = "bearer"`, **When** credentials are resolved, **Then** the resulting Credentials struct specifies `Authorization: Bearer {token}` header injection
- [ ] **Given** a credential mapping with `injection = "header"` and a custom header name, **When** credentials are resolved, **Then** the resulting Credentials struct specifies injection into the named custom header
- [ ] **Given** a credential mapping with `injection = "query_param"` and a parameter name, **When** credentials are resolved, **Then** the resulting Credentials struct specifies injection as a URL query parameter
- [ ] **Given** the `CredentialProvider` trait definition, **When** a community developer reads the trait, **Then** the trait is documented and designed to allow future implementations (Vault, AWS Secrets Manager, etc.) without changing the Sidecar core

## Technical Notes

- The `CredentialProvider` trait should be defined in the sidecar's domain layer, not tied to any specific backend
- Trait signature (approximate):
  ```rust
  #[async_trait]
  pub trait CredentialProvider: Send + Sync {
      async fn resolve(&self, target: &str) -> Result<Credentials, CredentialError>;
  }
  ```
- `Credentials` is an enum or struct describing the injection mode:
  - `Bearer { token: SecretString }` — inject as `Authorization: Bearer {token}`
  - `Header { name: String, value: SecretString }` — inject as custom header
  - `QueryParam { name: String, value: SecretString }` — inject as URL query parameter
- Use `secrecy::SecretString` (or equivalent) to prevent accidental logging of credential values
- Config-based implementation reads from TOML structure like:
  ```toml
  [[credentials]]
  target = "api.openai.com"
  injection = "bearer"
  source = "env"
  env_var = "OPENAI_API_KEY"
  ```
- Environment variables are read at resolution time (not cached at startup) to support rotation without restart
- Target matching should support exact host match; wildcard matching (e.g., `*.openai.com`) is a future enhancement
- The config-based provider should validate all mappings at startup (fail-fast on missing env vars if `source = "env"` and `fail_on_missing = true`)

## Dependencies

### Requires

- None (trait definition is foundational for this unit)

### Enables

- 003-credential-injection (consumes `CredentialProvider` to resolve credentials before dispatch)

## Edge Cases

| Scenario | Expected Behavior |
| -------- | ----------------- |
| Target host has no credential mapping configured | `resolve()` returns `Ok(Credentials::None)` — request dispatched without credentials |
| Environment variable specified in mapping does not exist | `resolve()` returns `Err(CredentialError::EnvVarMissing)` — upstream caller decides to deny |
| Environment variable exists but is empty | `resolve()` returns `Err(CredentialError::EmptyCredential)` — treated as missing |
| Multiple credential mappings for the same target host | Rejected at config load time (validation error, fail-fast) |
| Credential mapping with unknown injection type | Rejected at config load time (validation error, fail-fast) |
| Credential mapping with unknown source type | Rejected at config load time (validation error, fail-fast) |
| Config file value contains whitespace or special characters | Value used as-is after trimming; no escaping applied |
| Target host includes port (e.g., `api.example.com:8443`) | Matched including port; `api.example.com` and `api.example.com:8443` are distinct targets |

## Out of Scope

- Dynamic secret providers (Vault, AWS Secrets Manager, GCP Secret Manager) — V1 is config-based only
- Credential rotation notifications or TTL-based refresh
- Wildcard target matching (e.g., `*.openai.com`)
- Mutual TLS (mTLS) client certificate injection
- OAuth2 token exchange flows
- Credential caching across requests (environment variables re-read each time)
