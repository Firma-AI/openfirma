---
title: Govern Composio tool execution
description: Route hosted MCP and backend Composio calls through OpenFirma with pinned tool catalogs.
---

OpenFirma can govern Composio tool execution without running another gateway.
The existing Sidecar HTTPS boundary decodes Composio requests, maps tools to
canonical action classes, evaluates Cedar, and audits one event per logical
tool action.

## Configure the mapping

Add the built-in mapping to an existing project:

```bash
firma config --profile generic --mapping composio
```

The generated configuration enables strict HTTPS interception for
`app.composio.dev` and `backend.composio.dev`. Do not add those hosts to
`bypass_hosts`; opaque CONNECT traffic cannot be decoded at Layer 7.

Continue to run your chosen command:

```bash
firma run --profile generic -- your-agent
```

`firma run` does not start Composio or PAI. It starts or reuses the normal
OpenFirma components, configures the proxy and CA, and executes the command you
provided.

## Route both PAI paths

PAI reaches Composio through two independent paths:

- the runtime calls the hosted MCP endpoint;
- the backend calls direct execution and Tool Router endpoints.

Both processes must use the OpenFirma HTTP/HTTPS proxy and trust the Firma CA.
Production PAI startup fails when Composio is enabled without both settings.
A failed proxied request is not retried directly.

PAI keeps its `pai-assistant:<bot_uuid>` user value. The account value carried
by a request may be an identifier or alias; audit records preserve that
selector but do not claim it is a provider-confirmed identity.

## Understand policy resources

Each decoded tool uses a transport-independent resource:

```text
composio://gmail/GMAIL_SEND_EMAIL
```

The connector still dispatches the original HTTPS request. The logical
resource is used only for capability scope, Cedar, provenance, session history,
and audit.

An exact-resource Cedar rule can block one tool:

```cedar
forbid (
    principal,
    action == Firma::Action::"communication.external.send",
    resource == Firma::Resource::"composio://gmail/GMAIL_SEND_EMAIL"
);
```

Policies can also use optional context fields:

```cedar
forbid (
    principal,
    action,
    resource
) when {
    context has composio_toolkit &&
    context.composio_toolkit == "gmail" &&
    context.composio_batch_size > 1
};
```

The context includes toolkit, exact slug, user selector, account selector,
session identifier, and batch position when those values are present.

## Atomic batches

`COMPOSIO_MULTI_EXECUTE_TOOL` is all-or-nothing. OpenFirma decodes every child
before dispatch and evaluates them in input order.

- If every child is allowed, the original request is dispatched once.
- If any child blocks, the request is not dispatched.
- Allowed siblings are audited as aborted for batch atomicity.
- Monitor mode dispatches once and retains each would-block reason.

OpenFirma never splits, reorders, or partially forwards the batch.

## Catalog pins and unsupported tools

The Sidecar ships reviewed catalogs for Gmail (63 tools) and Google Calendar
(49), both pinned at toolkit version `20260721_00`. They are compiled into the
binary, so enforcement never queries Composio on the hot path and a tool is
governed the same way on every host.

Each slug carries a manually assigned canonical class, so policies stay
transport-independent:

| Tool                          | Action class                  |
| ----------------------------- | ----------------------------- |
| `GMAIL_FETCH_EMAILS`          | `communication.external.read` |
| `GMAIL_SEND_EMAIL`            | `communication.external.send` |
| `GOOGLECALENDAR_FIND_EVENT`   | `calendar.read`               |
| `GOOGLECALENDAR_DELETE_EVENT` | `calendar.delete`             |

Refreshing a toolkit is a maintainer task, not an operator one: see
[Composio enforcement](https://github.com/Firma-AI/openfirma/blob/main/docs/architecture/composio-enforcement.md)
for the refresh and review loop.

Unknown toolkits, missing slugs, version mismatches, malformed execution
payloads, custom tools, raw proxy execution, and shell or workbench tools fail
closed. Slack and Notion remain unsupported until each has a complete reviewed
catalog, so every Slack or Notion tool call is denied at the boundary.

## Audit safety

Each logical action emits its own signed audit event. The canonical class and
the `composio://<toolkit>/<tool_slug>` resource identify the tool without
changing the shared protobuf contract. The event also records the decision and
shared dispatch outcome.

The event does not include API keys, OAuth tokens, authorization headers,
cookies, complete tool arguments, request selectors, or provider response
bodies.

See [Read and verify the audit log](../audit-log/) for sink and signature
details.
