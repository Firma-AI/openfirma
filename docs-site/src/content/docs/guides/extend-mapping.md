---
title: Extend the action-class mapping
description: Add a new SaaS provider — or any HTTP destination — to the Sidecar's mapping table without forking.
---

The Sidecar's mapping table tells the normalizer how to turn `(method, host, path)` tuples into canonical action classes. OpenFirma ships mappings for GitHub, Stripe, and Gmail. When you want to enforce on a destination that isn't covered — your own internal SaaS, a niche third-party, a new endpoint — you write a mapping file and merge it in.

This guide shows you how to write, validate, and ship a mapping extension.

You should already understand [Action classes](../../concepts/action-classes/) (what `action_class` is and why) and have a Sidecar running ([Run the sidecar standalone](../run-the-sidecar/)).

## Step 1: Decide what action classes the destination's calls map to

Before you write a single rule, decide which canonical classes the destination's endpoints belong to. The 44-class registry is documented in `docs/markdown/firma_action_class_registry.md` in the repository.

A useful exercise: list the destination's most common endpoints and what each one *does*, then assign the closest class. For a hypothetical `acme-saas.com` with three endpoints:

| Endpoint                              | What it does                       | Class                            |
| ------------------------------------- | ---------------------------------- | -------------------------------- |
| `GET /api/v1/users/<id>`              | Read a user record                 | `credential.read`                |
| `POST /api/v1/users/<id>/notify`      | Send a notification to the user    | `communication.external.send`    |
| `POST /api/v1/transfers`              | Move money between accounts        | `payment.transfer`               |

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
- **`host`** — exact match unless prefixed with `*.` for a single-label wildcard (`*.acme-saas.com` matches `api.acme-saas.com` and `auth.acme-saas.com` but *not* `api.dev.acme-saas.com`).
- **`path`** — exact match, with `*` as a wildcard for any single segment, and trailing `*` for "anything from here".
- **`action_class`** — must match an identifier the schema declares.

For wildcards, prefer specificity. `path = "*"` matches everything; `path = "/api/v1/*"` matches just under v1; `path = "/api/v1/users/*/notify"` matches a precise shape.

## Step 3: Merge the file into the Sidecar config

In `firma.toml`:

```toml
[sidecar.mapping]
rules_path        = "/path/to/default-mapping.toml"
rules_paths       = [
  "/path/to/acme-saas.toml",
]
default_protected = true
```

`rules_path` is the primary file (often the project's general mappings). `rules_paths` is a list of additional files merged in. The Sidecar concatenates all of them and:

- **Compiles** at startup. If any file is malformed or any rule references an unknown action class, startup fails fast.
- **Rejects duplicate `(method, host, path)` tuples** across all merged files. Fail-closed: if two files disagree on what an endpoint is, the Sidecar refuses to boot rather than guess.

This duplicate-detection is why merging works — you can ship a vendor-supplied file alongside your overrides and trust the Sidecar to surface conflicts.

## Step 4: Restart and verify

Restart the Sidecar. The startup log includes:

```text
INFO firma_sidecar::startup::mapping: loaded 3 mapping files
INFO firma_sidecar::startup::mapping: 47 total rules (44 base + 3 extension)
INFO firma_sidecar: sidecar ready
```

Make a test call:

```bash
curl --proxy http://127.0.0.1:8080 \
  https://api.acme-saas.com/api/v1/users/42
```

The audit event should show:

```json
{
  "envelope": {
    "intent": {
      "action_class": "credential.read",
      "resource": {
        "host": "api.acme-saas.com",
        "path": "/api/v1/users/42",
        "provider": null
      }
    }
  }
}
```

Note that `provider` is `null` — the provider field is set only for hosts in the Sidecar's known-allowlist (currently `github`, `stripe`, `gmail`). For your own destinations, the provider stays unset and policies key on `host` directly. That's fine and intentional; the registry of known providers is curated, not extensible at runtime.

## When to use `default_protected = true` vs `false`

Two stances:

**`default_protected = true` — fail-closed** (production default). Anything not in the mapping is denied. You discover gaps via DENY events, fill them in, and never let unknown traffic through.

**`default_protected = false` — passthrough** (development convenience). Unmapped traffic flows without enforcement. Easy to start with; dangerous to keep.

The shipped demo uses `false` so the demo can focus on its specific routes. Your real workloads should use `true`. Plan time to enumerate the destinations the agent legitimately uses before flipping the switch.

## Working with the shipped vendor mappings

The repo includes three large vendor files under `crates/firma-sidecar/config/mappings/`:

- `github.toml` — 44 GitHub REST endpoints → 12 classes.
- `stripe.toml` — 88 Stripe REST endpoints → 14 classes.
- `gmail.toml` — 41 Gmail REST endpoints → 7 classes.

Add them to `rules_paths`:

```toml
[sidecar.mapping]
rules_paths = [
  "crates/firma-sidecar/config/mappings/github.toml",
  "crates/firma-sidecar/config/mappings/stripe.toml",
  "crates/firma-sidecar/config/mappings/gmail.toml",
  "/path/to/your/extensions.toml",
]
```

These vendor files are reviewed and tested. Use them as-is; if you need to override a single rule, the easier path is to add the override to your extensions file and let the duplicate-detection at startup tell you about the conflict — then remove the original from your `rules_paths` rather than editing the vendor file.

## Common gotchas

**`unknown action class 'communications.external.send'` at startup.** Typo. The class is `communication.external.send` (singular). The schema is the source of truth — open `examples/demo/policies/schema.cedarschema` for the canonical list.

**`duplicate rule (POST, api.acme-saas.com, /api/v1/users/*)` at startup.** Two files disagree. Find the duplicate, decide which one wins, remove the loser.

**Calls match `default_protected` instead of your rule.** The rule's `host` or `path` is wrong. The most common mistake is `path = "/api/v1/users/42"` (exact ID) when the real path varies — use `/api/v1/users/*` instead.

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
