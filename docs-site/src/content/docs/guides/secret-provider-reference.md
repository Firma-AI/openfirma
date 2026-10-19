---
title: Secret provider reference
description: Built-in vault commands, custom provider fields, matchers, scopes, limits, and failure behavior.
---

This page is the detailed configuration and behavior reference for
placeholder-based secret providers. Start with [Secrets without handing them to
agents](../../concepts/secrets/) for the high-level workflow, or [Rehydrate &
mask secrets](../secret-gateway/) for managed setup. For fixed host-scoped
headers, use [credential injection](../inject-credentials/) instead.

## Built-in CLI providers

Bare names in `secret_providers` select built-ins. All built-ins run outside the
sandbox, return placeholders in place of extracted values, and block every
command shape not explicitly classified below.

| Provider | Credential environment | Sensitive commands | Safe commands | Explicitly blocked commands |
| --- | --- | --- | --- | --- |
| [Bitwarden Secrets Manager](https://bitwarden.com/help/secrets-manager-cli/) (`bws`) | `BWS_ACCESS_TOKEN` | `secret list`, `secret get` | `project list`, `project get` | `run`; `secret create/edit/delete`; `project create/edit/delete` |
| [1Password](https://developer.1password.com/docs/cli/) (`op`) | `OP_SERVICE_ACCOUNT_TOKEN` | `item get` | `whoami`; `account/vault/item list` | `read`, `inject`, and every `document` command |
| [HashiCorp Vault](https://developer.hashicorp.com/vault/docs/commands) (`vault`) | `VAULT_TOKEN`, `VAULT_ADDR`, `VAULT_NAMESPACE` | `kv get` for a KV v2 response | `kv list`, `list`, `status`, `policy list` | `read`; `kv put/patch/delete/destroy/rollback/undelete/metadata` |
| [Doppler](https://docs.doppler.com/docs/cli) (`doppler`) | `DOPPLER_TOKEN` | `secrets download`; exact bare `secrets` | `me`; `projects/environments/configs list` | `run`; `secrets get/substitute/set/upload/delete`; every `secrets notes` command |

Scope is part of the built-in choice. 1Password (`op`) derives destination
authorities from each item's `urls[].href`. Bitwarden Secrets Manager (`bws`),
HashiCorp Vault (`vault`), and Doppler (`doppler`) have no domain selector, so
their placeholders are unscoped and can resolve for any request authority.
Define a custom CLI provider with a domain selector instead when destination
scoping is required.

Sensitive commands are normalized before execution:

- `bws secret list/get` forces JSON output.
- `op item get` forces JSON output. Field-scoped output such as `--fields`,
  `--otp`, or `--share-link` does not match the expected full-item response and
  the invocation is rejected during extraction. Every item must also contain at
  least one valid `urls[].href`; those authorities scope every extracted field,
  and an item without a valid URL is rejected.
- `vault kv get` forces JSON output and expects the KV v2 `data.data` shape.
  KV v1 responses, `-field`, and `-output-curl-string` do not match and are
  rejected during extraction.
- `doppler secrets download` forces JSON to stdout and disables fallback files.
  Bare `doppler secrets` forces JSON and removes raw output.

The built-ins also reject options that could redirect credentials or bypass
structured output:

| Provider | Always-forbidden options |
| --- | --- |
| Bitwarden Secrets Manager (`bws`) | `--server-url`/`-u`, `--config-file`/`-f`, `--profile`/`-p` |
| 1Password (`op`) | `--config` |
| HashiCorp Vault (`vault`) | address and agent-address overrides; TLS skip-verify, CA, client certificate/key, and server-name overrides |
| Doppler (`doppler`) | `--api-host`, `--no-verify-tls`, `--config-dir`, `--configuration`, `--print-config` |

Options that select a logical tenant without redirecting the server remain
available: Vault namespace and Doppler project/config selectors are recognized
when matching command words and passed to the real CLI.

## Custom CLI providers

A custom CLI provider is a full table; `type = "cli"` is required:

```toml
[run.defaults]
secret_providers = [
  { type = "cli", binary_name = "my-vault", provider_id = "my-vault", credential_env_vars = ["MY_VAULT_TOKEN"], stripped_options = [
    { name = "--account", takes_value = true },
  ], forbidden_options = [
    { name = "--server", takes_value = true },
    { name = "-k", takes_value = false },
  ], matchers = [
    { type = "sensitive_command", argv = ["secret", "get"], match = "prefix", stripped_options = [
      { name = "--format", takes_value = true },
    ], append_options = ["--format", "json"], matcher = { type = "json", record_path = "$", value_path = "$.value", name = { source = "path", path = "$.name" } } },
    { type = "safe_command", argv = ["status"], match = "exact" },
    { type = "blocked_command", argv = ["secret", "delete"], match = "prefix" },
  ] },
]
```

Integration fields:

- `binary_name`: one executable basename. Firma overlays every executable match
  on the effective host `PATH` with its private shim.
- `provider_id`: required integration identity used by the provider
  specification. It is not persisted or audited with individual extracted
  values.
- `credential_env_vars`: variables available to the real provider process.
  Firma removes these variables from the sandboxed command environment.
- `stripped_options`: integration-wide options ignored while identifying
  command words but retained when invoking the provider.
- `forbidden_options`: options that block the invocation even if a command rule
  would otherwise permit it.
- `matchers`: command classifications. Blocked rules win, then sensitive, then
  safe; an unrecognized command is blocked.

Command and option fields:

- `argv` excludes the executable name.
- `match = "prefix"` is the default and permits trailing positional arguments.
  `match = "exact"` permits only the listed positional command words. All
  dash-prefixed options, including unknown ones, are ignored during command
  classification and retained for provider execution unless a sensitive rule
  strips them. Enumerate every option that can redirect credentials, change
  behavior, or create side effects in `forbidden_options`.
- A sensitive rule's `stripped_options` are removed before execution;
  `append_options` are then inserted before any `--` end-of-options marker.
- Every option has `name` and `takes_value`. Set
  `allow_attached_value = true` only for options such as `-uVALUE`; it is invalid
  when `takes_value = false`. A required option value that is missing or
  interrupted by `--` blocks the invocation.

### Provider process environment and limits

The provider is noninteractive: stdin is null and stdout/stderr are fully
buffered. Its environment is cleared, then only declared
`credential_env_vars` and `PATH` are restored (`SYSTEMROOT` and `PATHEXT` are
also restored on Windows). `HOME` is deliberately absent, so a CLI that depends
on host home-directory state fails rather than reading it.

Declared credential variables are forwarded only when present; they are not
validated when `firma run` starts. A missing variable does not prevent provider
launch. The provider may fail itself, or a sensitive command may return an
unauthenticated shape that the matcher rejects at invocation time. Verify every
required provider variable before starting the run.

Managed `firma run` uses a fixed 10 MB broker response cap and permits at most
2.5 MB in each provider stdout and stderr stream. Exceeding either stream limit
rejects the whole invocation without replaying partial output. The shim also
uses a fixed 64 KiB serialized request cap, one-second connection timeout, and
five-second deadline for the complete broker operation, including provider
execution and response transfer. A deadline cancels the provider subprocess and
returns no usable output. There are currently no `firma.toml` fields to tune
these managed broker limits.

CLI matchers compile when a sensitive command is invoked. A compile error,
provider launch failure, output overflow, or stdout that does not match the
extraction schema rejects that invocation. The provider's actual exit status is
otherwise relayed with rewritten stdout and captured stderr. Matchers apply only
to stdout: stderr is replayed unchanged to the sandboxed process. Approve only
provider commands that never write secrets or credential-bearing diagnostics to
stderr.

## Secret matchers

CLI stdout and HTTP provider response bodies use the same matcher language.

### JSON matcher

```toml
matcher = {
  type = "json",
  record_path = "$.items[*]",
  value_path = "$.value",
  name = { source = "path", path = "$.name" },
  item_selector = { path = "$.title", scope = "document" },
  domain_selector = { path = "$.urls[*].href", scope = "document" },
}
```

- `record_path` runs once against the document and selects logical records.
- `value_path` runs relative to each record and must select exactly one string.
- `name.source = "path"` requires exactly one non-empty string per record.
- `name.source = "record_key"` derives the name from the record's key in its
  parent object, useful for shapes such as `{ "API_KEY": "value" }`.
- `item_selector` is optional metadata. With `scope = "record"`, it must select
  exactly one node per record. With `scope = "document"`, it may select zero or
  one node and broadcasts it to every record. A selected non-string leaves the
  item absent; an empty string is invalid.
- `domain_selector` is optional and may select multiple values. Record scope
  evaluates per record; document scope evaluates once and broadcasts. Once
  configured, every applicable root must produce at least one valid string
  domain. Zero matches, non-strings, or invalid domains reject the complete
  extraction before any placeholder is minted.

### Regex matcher

```toml
matcher = {
  type = "regex",
  pattern = "(?m)^(?P<name>[^=]+)=(?P<value>[^@]+)@(?P<domain>.+)$",
}
```

The pattern must contain named `name` and `value` capture groups. `name` must be
non-empty. An optional named `domain` group scopes the placeholder; if the
pattern defines that group, every match must populate it with a valid domain.
No matches, invalid UTF-8, or invalid captures reject the complete extraction.

## Domain-scoped rehydration

Domains may be bare HTTP authorities (`api.example.com` or
`api.example.com:8443`) or URLs. URL scheme, path, query, fragment, and userinfo
are discarded; every explicit port remains part of the authority, including
`:80` and `:443`. Values are normalized and deduplicated.

A scoped placeholder resolves only when the outbound request authority matches
one of its domains exactly. An explicitly scoped `api.example.com:443` does not
match a request authority that omits `:443`. A mismatch is handled like an
unknown placeholder: the whole request fails closed and no partially rehydrated
body is dispatched.

If `domain_selector` is omitted, the placeholder is **unscoped** and can resolve
for any request authority. OpenFirma does not infer the destination from the
vault host because a vault normally returns credentials intended for another
service. Configure a domain selector whenever provider metadata identifies the
intended destination.

## Custom HTTP providers

HTTP providers are always full custom tables; there are no built-in HTTP
providers.

```toml
[run.defaults]
secret_providers = [
  { type = "http", provider_id = "internal-vault", host = "vault.example.com", matchers = [
    { type = "blocked_command", path = "/v1/secret/delete/*" },
    { type = "sensitive_command", path = "/v1/secret/*", matcher = { type = "json", record_path = "$", value_path = "$.data.value", name = { source = "path", path = "$.data.name" }, domain_selector = { path = "$.data.url", scope = "record" } } },
    { type = "safe_command", path = "/v1/health" },
  ] },
]
```

- `provider_id` identifies the integration.
- `host` is a glob where `*` matches any character sequence, including across
  DNS labels. A directly configured Sidecar uses list order when multiple hosts
  match. Managed `firma run` retains inherited Sidecar-template providers in
  list order, removes a template entry only when a profile provider has the same
  `provider_id`, then appends profile providers in lexicographic ID order. The
  first matching entry in that effective sequence wins. Avoid overlapping host
  patterns across both sources.
- Provider matching removes an explicit `:80` or `:443` from both the pattern
  and request host without considering the request scheme. A pattern such as
  `vault.example.com:443` therefore cannot restrict matching to HTTPS and may
  also classify HTTP traffic normalized to the same portless host. Enforce
  transport separately rather than relying on these ports in the provider
  pattern.
- HTTP rules resolve blocked first, sensitive second, and safe third. An unknown
  path is blocked. A sensitive rule may omit `path` to become the fallback for
  every path on that provider host; safe and blocked paths must be non-empty.
- A blocked path is rejected before dispatch. A safe path is returned
  unmodified. A sensitive path must produce the configured secret shape.

Provider host globs and HTTPS MITM patterns are different languages. For
example, a provider host may use `secretsmanager.*.amazonaws.com`, but MITM only
accepts exact hosts or a leading suffix wildcard such as `*.amazonaws.com`,
which matches one or more preceding labels. It rejects mid-name wildcards and
broad top-level patterns such as `*.com`. Configure both independently for
HTTPS.

HTTP matchers compile when the Sidecar starts; invalid JSONPath or regex syntax
prevents startup. After a sensitive response is dispatched, any extraction
failure aborts it with `CREDENTIAL_INJECTION_FAILED`, including:

- invalid JSON/text or no selected records/matches;
- wrong selector type or cardinality, empty names, or invalid/missing domains;
- unsupported or corrupt content encoding;
- expansion beyond `sidecar.interceptor.max_decompressed_body_size`;
- recompression failure; or
- failure to push an extracted value to the gateway.

The agent never receives a partially rewritten sensitive response or an
unresolvable newly minted placeholder.

## Compression and masking limits

Secret rehydration, HTTP extraction, and inbound masking can decode absent or
`identity` encoding directly and support `gzip`, zlib-wrapped or raw `deflate`,
Brotli (`br`), and Zstandard (`zstd`). Successfully rewritten bodies are
recompressed with the same encoding.

The default output limit for decompression is 16 MB per request or response and
is configured with:

```toml
[sidecar.interceptor]
max_decompressed_body_size = "16MB"
```

The limit is enforced only while expanding gzip, deflate, Brotli, or Zstandard
content. Absent/`identity` bodies are not bounded by
`max_decompressed_body_size`; this setting is not a general body-size or memory
limit. For sensitive HTTP-provider extraction and inbound masking,
unsupported/corrupt compressed encodings and compressed bodies whose expanded
output exceeds the limit fail closed rather than pass through uninspected.
Outbound rehydration differs: after a decode or decompression-size failure, the
Sidecar scans the raw encoded bytes. It denies when those bytes visibly contain
a placeholder-shaped token; otherwise it cannot establish that opaque content
needs rehydration and passes the body through unchanged.

Inbound response masking applies only to values rehydrated into the current
request and intentionally ignores those shorter than eight bytes. Short values
collide too easily with ordinary response content, so masking them would corrupt
unrelated data. They can still be extracted, represented by placeholders, and
rehydrated outbound, but an echo in that request's response is returned
unmasked. Do not rely on inbound masking for PINs, short codes, or any other
secret below this floor.

Masking is content-type aware. Raw bodies use exact byte-substring matching.
JSON, form, and XML bodies recognize their corresponding escaped or encoded
forms, but only at word boundaries; adjacent alphanumeric, `-`, or `_`
characters suppress the structured match. An upstream that embeds a secret in
such a larger token can therefore return it unmasked even when it exceeds eight
bytes.

## Current path limitation

Requests handled by OpenFirma's dedicated Composio path currently bypass secret
placeholder rehydration, inbound masking, and custom HTTP provider interception.
A placeholder in such a request is forwarded literally, and an echoed known
secret is not masked. Do not rely on the secret gateway for Composio traffic.
