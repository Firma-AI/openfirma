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
evaluation. Account-lifecycle requests are governed, not passed through:
`POST`/`PATCH`/`PUT`/`DELETE` on the `connected_accounts` and `auth_configs`
routes, writes to the Tool Router session `link` route, and
`PATCH`/`PUT`/`DELETE` on a Tool Router `session/{id}` resource (all under
both `/api/v3` and `/api/v3.1`) decode into one logical
`account.permission.change` action with a `composio://composio/<slug>`
resource (for example `COMPOSIO_CREATE_CONNECTED_ACCOUNT`,
`COMPOSIO_LINK_SESSION_ACCOUNT`, or `COMPOSIO_DELETE_SESSION`), so an agent
cannot expand or reshape its own reachable account surface without
capability and Cedar evaluation. `GET`/`HEAD`/`OPTIONS` on the
`connected_accounts` and `auth_configs` routes are governed as well, decoding
into one `credential.read` action with a
`composio://composio/COMPOSIO_LIST_CONNECTED_ACCOUNT` style resource (`LIST`
for the collection, `GET` for a single item): those responses disclose which
integrations exist and how they authenticate, which is credential
disclosure rather than discovery. As governed actions they also inherit the
query-string rule below, so a paginated listing is denied instead of
dispatched with an unevaluated filter. Session creation (`POST` to the session
collection) and `POST` to an existing `session/{id}` stay recognized
passthroughs, and tearing down the hosted MCP transport session via `DELETE`
on the MCP path remains transport-level passthrough. Every recognized route
carries a method allowlist: reads (`GET`/`HEAD`/`OPTIONS`) pass through, MCP
session paths additionally allow `DELETE` for teardown, lifecycle writes are
governed, and any other method fails closed rather than auditing as
passthrough. `POST` is not a read: apart from the two Tool Router session
shapes above, a `POST` to a recognized read route (`tools`, `toolkits`, or a
session sub-collection) is denied, so a write can never reach Composio
through the discovery surface without capability and policy evaluation.
A governed request carrying a query string is denied outright:
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

Version pinning is enforced uniformly: every execution route funnels through
one gate. A request that omits the toolkit version is denied `unpinned_tool`,
and one naming a version other than the pin is denied `version_mismatch`, so
Composio can only ever execute the version the local snapshot classified.
Direct execution and Tool Router execution carry the version as a top-level
payload field. Hosted MCP JSON-RPC has no version slot of its own, so
`tools/call` reads the pin from the tool arguments alongside the account
selector, and `COMPOSIO_MULTI_EXECUTE_TOOL` reads it from each child entry.
This is a sharp edge for callers: an MCP client that cannot attach a
`version` argument cannot reach a governed tool at all.

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

Refreshing in place, onto the same version, keeps the existing reviewed
decisions and leaves only new slugs unmapped. A version bump writes a
new file name, so the reviewed decisions must be carried across explicitly
with `--previous-mapping`:

```bash
python3 scripts/composio_catalog.py refresh \
  --toolkit gmail \
  --version 20260801_00 \
  --snapshot crates/firma-sidecar/config/composio/gmail-20260801_00.json \
  --mapping crates/firma-sidecar/config/composio/gmail-20260801_00.mapping.json \
  --previous-mapping crates/firma-sidecar/config/composio/gmail-20260721_00.mapping.json
```

Without that flag every slug in the new pin starts unmapped. Known
limitation: the script matches on slug only. When Composio changes a tool's
description while keeping its slug, the carried-forward class is reused and
no re-review is triggered, so read the descriptions of already-classified
slugs periodically rather than trusting the diff to surface the change.

Classify each unmapped slug, then validate the pair before rebuilding:

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
  but a delete-only grant does let it create or update events. The decoder
  does not split it per operation the way it splits
  `COMPOSIO_MULTI_EXECUTE_TOOL`, because the batch shape is provider-specific
  and its children are not individually addressable tools.
- Slack's canvas-specific read, list, and delete tools are deprecated
  upstream in favor of generic file tools. Those replacements —
  `SLACK_RETRIEVE_DETAILED_INFORMATION_ABOUT_A_FILE`,
  `SLACK_LIST_FILES_WITH_FILTERS_IN_SLACK`, and `SLACK_DELETE_FILE` — stay
  under `communication.external.*` because they act on Slack files in
  general, not canvases, and raising them to `document.*` would
  over-classify routine attachment access. A policy meant to block canvas
  access entirely must name those three as well; Composio exposes no
  canvas-only equivalent, and the Sidecar cannot tell a canvas from an
  attachment without inspecting the file at runtime.
- `GMAIL_CREATE_PROMPT_POST` and `GMAIL_UPDATE_USER_ATTRIBUTES_VALUES` are
  Sanity CMS tools that Composio files under the `gmail` toolkit. Their
  descriptions mention the Sanity Content Agent and SAML value precedence,
  nothing Gmail-specific. They keep conservative classes and a
  `composio://gmail/...` resource, so the surprising toolkit is an upstream
  data-quality artifact rather than a classification gap.
- The Notion catalog has no `account.permission.change` entry. None of its
  56 tools manages sharing or permissions directly; Notion permissions
  inherit from the parent page. The absence reflects the toolkit surface,
  not an unreviewed area.

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
