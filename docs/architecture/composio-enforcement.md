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

Recognized read-only discovery requests (tool listings, toolkit metadata,
session reads, MCP session streams and teardown) can pass without tool-action
evaluation. Account-lifecycle writes are governed, not passed through:
`POST`/`PATCH`/`PUT`/`DELETE` on the `connected_accounts` and `auth_configs`
routes, writes to the Tool Router session `link` route, and
`PATCH`/`PUT`/`DELETE` on a Tool Router `session/{id}` resource (all under
both `/api/v3` and `/api/v3.1`) decode into one logical
`account.permission.change` action with a `composio://composio/<slug>`
resource (for example `COMPOSIO_CREATE_CONNECTED_ACCOUNT`,
`COMPOSIO_LINK_SESSION_ACCOUNT`, or `COMPOSIO_DELETE_SESSION`), so an agent
cannot expand or reshape its own reachable account surface without
capability and Cedar evaluation. Session creation (`POST` to the session
collection) stays a recognized passthrough, and tearing down the hosted MCP
transport session via `DELETE` on the MCP path remains transport-level
passthrough. Every recognized route carries a method allowlist:
reads (`GET`/`HEAD`/`OPTIONS`) pass through, MCP session paths additionally
allow `DELETE` for teardown, lifecycle writes are governed, and any other
method (for example `TRACE`) fails closed rather than auditing as
passthrough. A governed request carrying a query string is denied outright:
the query never participates in the policy decision, so it must not ride
along on an admitted dispatch. Hosted MCP paths deny query strings on every
method, discovery included, so a query-carrying MCP URL fails at
`initialize` with a clear denial instead of handshaking and then failing on
each `tools/call`. Unknown execution routes, JSON-RPC batches, malformed
payloads, unknown toolkits, unpinned slugs, custom tools, raw proxy
execution, and remote shell or workbench execution fail closed.

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

Two session-state consequences are deliberate and fail-conservative. Every
evaluated child enters the session's `prior_action_classes` history before
the batch verdict, so children later aborted for batch atomicity still
count toward policies like "deny after N sends" even though they never
dispatched. And when monitor mode forwards a batch in which every child
would have blocked, the dispatch carries no injected credentials, so the
observed upstream outcome (typically an auth failure) is not representative
of what a partially admitted batch would see.

## Pinned catalogs

Enforcement uses committed snapshots and reviewed mappings under
`crates/firma-sidecar/config/composio/`, compiled into the Sidecar binary and
loaded at startup:

| Toolkit         | Version       | Tools |
| --------------- | ------------- | ----- |
| Gmail           | `20260721_00` | 63    |
| Google Calendar | `20260721_00` | 49    |
| Slack           | `20260721_00` | 167   |
| Notion          | `20260730_00` | 56    |

A tool outside those snapshots is denied with `unknown_tool`, so a Composio
release that adds tools cannot widen what an agent may do until a maintainer
classifies the new slugs.

Version pinning is enforced asymmetrically because the routes carry
different information. Direct execution requires an explicit `version` field
matching the pin and is denied `unpinned_tool` without one. Tool Router
checks the version only when the request carries one, and hosted MCP calls
carry none, so on those routes Composio executes whatever version its
server currently serves while classification still comes from the pinned
snapshot; refresh pins promptly when Composio announces toolkit updates.

Pins are per pair, so Notion sitting on a later snapshot date than the other
three toolkits is expected; each pair is validated independently at startup.

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

## Classification caveats

Single-class mapping cannot express every provider nuance. Reviewed
judgement calls worth knowing when authoring policies:

- `GMAIL_UPDATE_VACATION_SETTINGS` is `communication.external.send`: the
  auto-responder emails an arbitrary body to every correspondent, so it is a
  send channel, not filter management.
- `GMAIL_CREATE_FILTER` stays `communication.external.filter`, but a filter
  action can forward matching inbound mail to an external address. Granting
  the class grants that forwarding path.
- `GOOGLECALENDAR_CREATE_EVENT` (`calendar.create`) emails invites with
  arbitrary text to arbitrary attendees, so it is an outbound channel even
  without a `communication.external.*` grant.
- `GOOGLECALENDAR_BATCH_EVENTS` multiplexes create, update, and delete in
  one call. It is pinned to `calendar.delete`, the highest-risk operation it
  can perform, so a capability that excludes deletes can never reach it —
  but a delete-only grant does let it create or update events.

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
