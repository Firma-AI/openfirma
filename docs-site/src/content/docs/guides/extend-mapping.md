---
title: Extend the action-class mapping
description: Add a new SaaS provider — or any HTTP destination — to the Sidecar's mapping table without forking.
---

The Sidecar's mapping table tells the normalizer how to turn `(method, host, path)` tuples into canonical action classes. OpenFirma ships mappings for GitHub, Stripe, and Gmail. When you want to enforce on a destination that isn't covered — your own internal SaaS, a niche third-party, a new endpoint — you write a mapping file and merge it in.

This guide shows you how to write, validate, and ship a mapping extension.

You should already understand [Action classes](../../concepts/action-classes/) (what `action_class` is and why) and have a Sidecar running ([Run the sidecar standalone](../run-the-sidecar/)).

## Step 1: Decide what action classes the destination's calls map to

File-based mappings belong to the local mini-authority's
`[authority].mapping_rules_paths`. Sidecars always consume complete snapshots
from an Authority and never read local mapping files. For Firma Team,
manage mappings centrally and generate remote configuration with `firma config
--mode agent-remote`; do not add local mapping paths. See
[Configuration setup](../initialize-a-project/) for migration and generation.

Before you write a single rule, decide which canonical classes the destination's endpoints belong to. The 52-class registry is documented in `docs/markdown/firma_action_class_registry.md` in the repository.

A useful exercise: list the destination's most common endpoints and what each one *does*, then assign the closest class. For a hypothetical `acme-saas.com` with three endpoints:

| Endpoint                         | What it does                    | Class                         |
| -------------------------------- | ------------------------------- | ----------------------------- |
| `GET /api/v1/users/<id>`         | Read a user record              | `credential.read`             |
| `POST /api/v1/users/<id>/notify` | Send a notification to the user | `communication.external.send` |
| `POST /api/v1/transfers`         | Move money between accounts     | `payment.transfer`            |

Three principles to keep in mind:

- **Class is semantic, not transport.** `payment.transfer` covers any way to move money — REST, SOAP, gRPC. The mapping is the join between transport and semantics; the class itself is transport-free.
- **Pick the *narrowest* class that's true.** `communication.external.send` covers paste services, webhooks, and Slack. `credential.read` is a tighter scope than `communication.external.send` even though they both involve reading. If both fit, pick the one that better describes the agent's intent.
- **Don't invent classes.** The registry is closed. If nothing fits cleanly, that's a signal to escalate the discussion in a real PR — not to make up a new identifier.

## Step 2: Write the mapping file

Create `acme-saas.toml` somewhere you can mount into the Sidecar. The format:

```toml
# Mappings for acme-saas.com.

[[rules]]
method       = "GET"
host         = "api.acme-saas.com"
path         = "/api/v1/users/*"
action_class = "credential.read"

[[rules]]
method       = "POST"
host         = "api.acme-saas.com"
path         = "/api/v1/users/*/notify"
action_class = "communication.external.send"

[[rules]]
method       = "POST"
host         = "api.acme-saas.com"
path         = "/api/v1/transfers"
action_class = "payment.transfer"
```

Field-by-field:

- **`method`** — uppercase HTTP verb. For HTTPS-tunneled traffic where you only have CONNECT-level visibility, use `"CONNECT"` here (see [HTTPS MITM](../https-mitm/) for the difference).
- **`host`** — exact match unless it contains `*`, which matches any sequence
  of characters *including dots*: `*.acme-saas.com` matches
  `api.acme-saas.com`, `auth.acme-saas.com`, **and** `api.dev.acme-saas.com`.
  There is no single-label form; if you need to exclude deeper subdomains,
  write exact hosts. Hosts are normalized at load time (lowercased, trailing
  dots stripped on either side of the port, default `:443`/`:80` port
  removed, nonstandard ports kept) to match how request hosts arrive, and
  two rules whose hosts differ only in that spelling count as duplicates and
  fail startup. Degenerate patterns that would silently normalize into a
  catch-all (such as `*.` or `*:443`) or into an empty name (such as
  `:443`) are rejected at startup; write `*` explicitly if you mean it.
- **`path`** — exact match unless it contains `*`, which likewise crosses
  `/` separators; a trailing `*` means "anything from here".
- **`action_class`** — must match an identifier from the action-class registry.

For wildcards, prefer specificity. `path = "*"` matches everything; `path = "/api/v1/*"` matches anything under v1 at any depth; `path = "/api/v1/users/*/notify"` matches that shape with any middle section.

## Step 3: Select the file in Authority configuration

For the local mini-authority, add the file to the complete producer list in
`firma.toml`, keeping the existing files:

```toml
[authority]
mapping_rules_paths = [
  "/path/to/default-mapping.toml",
  "/path/to/acme-saas.toml",
]
```

The Authority concatenates the selected files in order. Relative paths resolve
against the Authority config directory. It:

- **Compiles** at startup. If any file is malformed or any rule references an unknown action class, startup fails fast.
- **Rejects duplicate `(method, host, path)` tuples** across all merged files. Conflicting inputs cannot be published.

At least one mapping file is required; an omitted or empty path list is invalid.
A selected file that is empty, holds only comments, or contains `rules = []`
publishes no rules. When no selected file has rules, the snapshot is
intentionally deny-all.
This requirement also applies to config-consuming Authority administration and
offline issuance commands, although offline issuance does not load the mappings.

## Step 4: Restart and verify

Restart the Authority after changing its configured file list. File-content
changes are watched in daemon mode: valid updates publish mappings, policy and
schema together; invalid reloads retain the accepted generation. The connected
Sidecar logs `enforcement snapshot swapped` when a complete generation activates.
Locally owned `firma run` inputs are frozen before agent startup; restart the run
to use authored changes.

Make a test call:

```bash
curl --proxy http://127.0.0.1:8080 \
  https://api.acme-saas.com/api/v1/users/42
```

The audit event should show:

```json
{
  "action": "credential.read",
  "resource": "api.acme-saas.com/api/v1/users/42"
}
```

Note that the audit event records the resource as an opaque UID. The internal `provider` hint is set only for hosts in the Sidecar's known allowlist (currently `github`, `stripe`, `gmail`). For your own destinations, policies should key on the exact resource UID.

## Upgrade existing configuration

Mappings are owned exclusively by the Authority. Move the former Sidecar primary
and extra paths into `[authority].mapping_rules_paths`, in the same order, and
remove `[sidecar.mapping]` and any nested enforcement mapping settings. Configure
`[sidecar.authority].url`; a directly launched Sidecar still needs an Authority.
For a remote deployment, configure mappings on that Authority instead of placing
paths on the Sidecar machine.

Configs whose `[authority]` section an earlier `firma run` first-run prompt
wrote have no `mapping_rules_paths`. `firma run` backfills them automatically
with the generated `mapping-rules.toml`. The Authority rejects any other
`[authority]` section without the key until you add it.

Legacy Sidecar mapping keys are rejected by every command that reads the file,
including the Authority, the Sidecar, and `firma config` when it validates
existing configuration. Repair those keys before regenerating. The
former `default_protected=false` bypass has no replacement: unmatched traffic is
always denied. Add explicit rules for legitimate destinations and inspect DENY
events for gaps.

When rerunning `firma config`, generated `mappings/<vendor>.toml` selections are
updated independently of their position in the list, however the path is
spelled. Custom mapping paths are preserved and duplicate paths, including
different spellings of one file, are removed; a custom file with a vendor
basename outside `mappings/` remains an authored source unless it is a link to
the generated file.

## Working with the shipped vendor mappings

The repo includes four vendor files under `crates/firma-sidecar/config/mappings/`:

- `github.toml` — GitHub REST + smart HTTP → 12 classes.
- `stripe.toml` — 88 Stripe REST endpoints → 14 classes.
- `gmail.toml` — 41 Gmail REST endpoints → 7 classes.
- `composio.toml` — Composio execution transports and hosted MCP → 1 class. It is coarse on purpose: the per-tool class comes from the pinned catalogs described in the [Composio guide](../composio/), not from the path.

Add them to `mapping_rules_paths`:

```toml
[authority]
mapping_rules_paths = [
  "crates/firma-sidecar/config/mappings/github.toml",
  "crates/firma-sidecar/config/mappings/stripe.toml",
  "crates/firma-sidecar/config/mappings/gmail.toml",
  "crates/firma-sidecar/config/mappings/composio.toml",
  "/path/to/your/extensions.toml",
]
```

These vendor files are reviewed and tested. Duplicate matchers are rejected, so
an extension cannot silently override a vendor rule. Select a nonconflicting
authored file instead when changing an existing matcher.

## Common gotchas

**`unknown action class 'communications.external.send'` at startup.** Typo. The class is `communication.external.send` (singular). The action-class registry is the source of truth.

**`duplicate rule (POST, api.acme-saas.com, /api/v1/users/*)` at startup.** Two files disagree. Find the duplicate, decide which one wins, remove the loser.

**Calls are denied as unclassified.** Check the rule's `host` and `path`. A path
such as `/api/v1/users/42` matches only that exact ID; use `/api/v1/users/*` for
variable IDs.

**HTTPS calls don't get matched.** Without MITM, the Sidecar only sees `CONNECT host:443`. Either set `method = "CONNECT"` in your rule (destination-level policy only) or [enable MITM for the host](../https-mitm/) so the inner method/path is visible.

## A pattern for new SaaS providers

When you want a new vendor file (one you'd want to upstream), this is the workflow that reads as production-quality:

1. Inventory the API surface from the vendor's reference docs. Group endpoints by capability category.
2. For each group, decide the closest class. Lean on the existing `github.toml` / `stripe.toml` patterns.
3. Write the file with comments above each section explaining the mapping rationale.
4. Test with `curl` calls against the live API (or recordings) and confirm the audit log shows the expected class.
5. Open a PR. The repo accepts vendor mapping files that follow this shape.

The goal is for the mapping file to read like a *spec* — someone reviewing six months from now should be able to tell what was intended without re-reading the vendor's API docs.

## What's next

- [Concepts: Action classes](../../concepts/action-classes/) — the design rationale for the registry.
- [Inject credentials](../inject-credentials/) — pair mappings with credential injection for the destinations.
- [Write your first Cedar policy](../write-a-cedar-policy/) — write rules for the new classes.
