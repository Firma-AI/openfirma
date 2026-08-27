# firma-authority

`firma-authority` is the local Authority included with Firma OSS. It is the source of permission for local development and demos: it loads policy, signs short-lived permission tokens, and streams policy and revocation updates to Sidecars.

> This Mini Authority is not a production control plane. It has no high availability, HSM integration, management-plane access control, or production audit backend. Run it on localhost or in isolated development and CI environments.

## How it fits into Firma

The Authority answers the first permission question: can this agent receive a token for these actions and resources?

If the request is allowed, the Authority signs a permission token. The Sidecar later verifies that token locally on each outbound request. The Sidecar also keeps its policy and revocation state fresh by subscribing to Authority streams.

```text
Agent session starts
        |
        | request permission
        v
firma-authority ---- signed token ----> Sidecar / agent runtime
        |
        | policy and revocation streams
        v
firma-sidecar enforces locally on each request
```

The important point is that the Authority is not on the hot path for every outbound call. It issues permission and distributes state; the Sidecar enforces locally.

## Quick start

Build the binary:

```bash
cargo build -p firma-authority
```

Generate a signing key:

```bash
cargo run -p firma-authority -- generate-key --output firma-authority.key
```

This writes two files:

- `firma-authority.key`, the private signing key. Keep this secret.
- `firma-authority.pub`, the public verification key. Give this to Sidecars.

Create a `firma.toml`. Every subcommand reads one shared, sectioned
`firma.toml`; the Authority reads the `[authority]` section. See the Config
Discovery section in [`docs/cli.md`](../../docs/cli.md) for the discovery
precedence; `--config <path>` only relocates the file.

```toml
[authority]
listen_addr = "[::1]:50051"
policy_dir = "examples/policies"
revocation_file = "revocations.txt"
key_file = "firma-authority.key"
max_ttl = "1h"
bundle_ttl = "30s"
```

Start the Authority (discovers `firma.toml`, or pass `--config`):

```bash
cargo run -p firma-authority -- --config firma.toml
```

`policy_dir` must contain at least one `.cedar` policy. The binary includes the default schema, so a `schema.cedarschema` file is optional unless you want to override it.

## Issue a permission token

For local demos, you can issue a token into a seed file that the Sidecar loads at startup:

```bash
cargo run -p firma-authority -- --config firma.toml issue   --agent-id agt_01j0000000e008000000000001   --session-id demo-session   --action communication.external.send   --resource-scope '*'   --ttl-seconds 3600   --output capability-demo-agent.toml
```

The output file contains the signed token and matching claims. Configure the Sidecar with the Authority public key and list the seed file under `[capability_seed].paths`.

## Configuration

| Key                  | Default               | Purpose                                      |
| -------------------- | --------------------- | -------------------------------------------- |
| `listen_addr`        | `[::1]:50051`         | gRPC address for the Authority service.      |
| `policy_dir`         | `policies`            | Directory containing `.cedar` policy files.  |
| `schema_path`        | unset                 | Optional schema override.                    |
| `revocation_file`    | `revocations.txt`     | File containing canonical `ctok` token IDs.  |
| `key_file`           | `firma-authority.key` | Authority private signing key.               |
| `max_ttl`            | `"1h"`                | Maximum token lifetime.                      |
| `bundle_ttl_seconds` | `30`                  | TTL advertised with streamed policy bundles. |

Every key can be overridden with a `FIRMA_AUTHORITY_` environment variable. For example, `FIRMA_AUTHORITY_LISTEN_ADDR` overrides `listen_addr`.

## Policy files

The Authority loads every `.cedar` file in `policy_dir` and streams the resulting bundle to connected Sidecars. Cedar is default-deny: if no permit applies, the request is denied. Forbid rules override permit rules.

Example policies live in `examples/policies/`.

Entity identifiers follow this shape:

| Role      | Format                              |
| --------- | ----------------------------------- |
| Principal | `Firma::Agent::"<agent_id>"`        |
| Action    | `Firma::Action::"<action_class>"`   |
| Resource  | `Firma::Resource::"<resource_uri>"` |

The Sidecar supplies request context such as session ID, timestamp, serialized parameters, risk score, and action count when it evaluates policy.

## Services

`firma-authority` implements `firma.v1.AuthorityService`.

`IssueCapability` evaluates policy and returns either a signed token or a denial reason.

`WatchPolicyBundle` streams the current policy bundle immediately on connect and again whenever policies change.

`WatchRevocations` streams token revocation events so Sidecars can deny revoked tokens locally.

## Revoke a token

```bash
cargo run -p firma-authority -- --config firma.toml revocations add <token-id> --reason "session-terminated"
```

A connected Sidecar receives the revocation on the stream and denies later requests that use the revoked token.

To compact expired revocation entries:

```bash
cargo run -p firma-authority -- --config firma.toml revocations compact
```

## Docker

```bash
docker build -f crates/firma-authority/Dockerfile -t firma-authority .

docker run --rm   -p 50051:50051   -v /path/to/policies:/app/policies:ro   -v /path/to/data:/app/data   -e FIRMA_AUTHORITY_KEY_FILE=/app/data/firma-authority.key   firma-authority
```

Mount your own policy directory when you want to test custom policies.
