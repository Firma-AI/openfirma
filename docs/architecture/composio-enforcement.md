# Composio enforcement

OpenFirma governs Composio as an external Layer 7 protocol inside the existing
Sidecar boundary. It does not start Composio, add Redis, or create another
network namespace.

## Request path

A command started with `firma run` inherits the existing HTTPS proxy and Firma
CA settings. PAI uses that same boundary in two places:

- its agent runtime calls Composio's hosted MCP endpoint;
- its backend calls the direct execution and Tool Router APIs.

The Sidecar terminates TLS for the protected Composio hosts, decodes the
execution request, maps every requested tool through a pinned local catalog,
evaluates each logical action with the normal capability and Cedar stages, and
audits the result. The original HTTP request is dispatched once only after all
logical actions are admitted.

## Supported execution routes

The decoder recognizes:

- hosted MCP JSON-RPC `tools/call`, under either protected host;
- `POST /api/v3/tools/execute/{tool_slug}`;
- `POST /api/v3.1/tool_router/session/{session_id}/execute`;
- supported Composio execution meta-tools;
- `COMPOSIO_MULTI_EXECUTE_TOOL`, with one logical action per child.

Recognized discovery and lifecycle requests can pass without tool-action
evaluation. Unknown execution routes, JSON-RPC batches, malformed payloads,
unknown toolkits, unpinned slugs, custom tools, raw proxy execution, and remote
shell or workbench execution fail closed.

## Logical and transport resources

Policy and audit use a logical resource:

```text
composio://<toolkit>/<tool_slug>
```

The connector keeps the original HTTPS scheme, host, path, headers, and body.
OpenFirma never constructs an upstream URL from the logical resource. Internal
`x-firma-*` headers are stripped before dispatch, and raw tool arguments are
not copied into resources or ordinary logs.

## Atomic multi-tool requests

OpenFirma decodes and evaluates every child in input order. In enforce mode, a
deny or remediation outcome blocks the entire request and admitted siblings are
audited as aborted for batch atomicity. The connector is called zero times.

When every child is allowed, the original request is dispatched exactly once
and the same connector outcome is copied to every child audit event. Monitor
mode also dispatches once while retaining each would-block reason.

## Pinned catalogs

Enforcement uses committed snapshots and reviewed mappings under
`crates/firma-sidecar/config/composio/`, compiled into the Sidecar binary and
loaded at startup:

| Toolkit         | Version       | Tools |
| --------------- | ------------- | ----- |
| Gmail           | `20260721_00` | 63    |
| Google Calendar | `20260721_00` | 49    |
| Slack           | `20260721_00` | 167   |

A tool outside those snapshots is denied with `unknown_tool`, so a Composio
release that adds tools cannot widen what an agent may do until a maintainer
classifies the new slugs.

Refreshes are maintenance operations, never hot-path network calls:

```bash
python3 scripts/composio_catalog.py refresh \
  --toolkit gmail \
  --version 20260721_00 \
  --snapshot crates/firma-sidecar/config/composio/gmail-20260721_00.json \
  --mapping crates/firma-sidecar/config/composio/gmail-20260721_00.mapping.json
```

The refresh keeps existing reviewed decisions and leaves every new slug
unmapped. Classify each one, then validate the pair before rebuilding:

```bash
python3 scripts/composio_catalog.py validate \
  --snapshot crates/firma-sidecar/config/composio/gmail-20260721_00.json \
  --mapping crates/firma-sidecar/config/composio/gmail-20260721_00.mapping.json
```

Provide `COMPOSIO_API_KEY` through the operator's secret manager before running
the command. The script uses it only for the read-only request and never writes
it to the snapshot or error output. Every new slug remains unmapped until a
reviewer assigns a canonical class. Validation rejects missing mappings,
unknown classes, version drift, and source/mapping differences.

## Cedar policy

Composio actions use the existing canonical classes. Policies can also match
the logical resource and optional Composio context:

```cedar
forbid (
    principal,
    action == Firma::Action::"communication.external.send",
    resource == Firma::Resource::"composio://gmail/GMAIL_SEND_EMAIL"
) when {
    context.composio_user_id == "pai-assistant:restricted-bot"
};
```

Available optional fields are `composio_toolkit`, `composio_tool_slug`,
`composio_user_id`, `composio_account`,
`composio_session_id`, `composio_batch_index`, and
`composio_batch_size`. Account values can be identifiers or aliases supplied
with the request; they are not proof of the account Composio ultimately chose.

All context is local and deterministic. Enforcement performs no catalog or
policy network lookup on the hot path.
