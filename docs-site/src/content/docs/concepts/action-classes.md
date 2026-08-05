---
title: Action classes
description: The canonical vocabulary that connects raw HTTP traffic to the policies that govern it.
---

This page explains what action classes are, where the vocabulary comes from, and how a raw `(method, host, path)` tuple gets turned into one. If you've read [The enforcement pipeline](../pipeline/), you'll recognize this as what the normalizer does.

## Why a fixed vocabulary?

Imagine writing a policy that says "the agent cannot exfiltrate data". Without a fixed vocabulary, you'd have to enumerate every host and path that *could* be used for exfiltration: every paste service, every issue tracker, every webhook endpoint, every SMTP relay. The list is infinite, and the next service is always invented after you wrote your policy.

Action classes invert the problem. Instead of policies enumerating *destinations*, they speak in terms of *what the agent is doing semantically*. A `POST` to `paste.rs/`, a `POST` to `gist.github.com/api/v1/gists`, and an SMTP send are all instances of `communication.external.send` — and a single forbid rule covers all of them.

Three properties make this useful in practice:

1. **Transport-independent.** The class describes the action, not how it's delivered. `payment.transfer` is the same class whether it's a Stripe API call or a banking SOAP request. The protocol rule is simple: transport names and provider names do not appear in action identifiers.
2. **Closed set.** New classes are added by editing a registry, not at runtime. The list is finite and reviewable.
3. **Deterministic mapping.** A given `(method, host, path)` always produces the same class. There's no LLM in the loop on the hot path — see [Architecture & invariants](../architecture/) for why this matters.

## Benefits and tradeoffs

Benefits:

- **Portable policies.** If your rule is "don't send data outside the company", it should keep working when the agent switches from one email API to another, or when a connector changes from REST to gRPC. The policy cares about `communication.external.send`; the connector and mapping table care about the transport details.
- **Readable audit logs.** Instead of asking whether `POST /v1/payment_intents/:id/confirm` is dangerous, you see `payment.transfer` and can group similar events across providers.
- **Predictable enforcement.** The hot path stays a table lookup plus policy evaluation. There is no probabilistic classifier deciding what the action means at request time.

Costs:

- **Mapping maintenance.** Somebody has to keep provider endpoints classified. A fixed vocabulary is only useful when important endpoints map to the right class.
- **Coarse semantics.** A class like `communication.external.send` is intentionally broad. If a policy needs provider-specific nuance, that nuance has to live in resource fields or provider-specific classes.
- **Slower evolution.** New action semantics require a registry change and a mapping update. OpenFirma chooses that maintenance burden deliberately because the alternative is policy logic tied to every vendor URL shape.

## The registry

OpenFirma ships with **48 canonical action classes**. The base 15 come from
**FEP v0.1**, the versioned Firma protocol specification that defines the
canonical registry and its invariants. The remaining classes extend that base
for GitHub (12), Stripe (12), Gmail (5), and Google Calendar (4).

The 15 FEP v0.1 base classes give you a feel for the granularity:

```text
account.permission.change     filesystem.delete
browser.purchase              filesystem.read
communication.external.send   filesystem.write
communication.internal.send   memory.cross_namespace.read
credential.read               memory.cross_namespace.write
credential.write              payment.purchase
                              payment.transfer
                              system.execute
                              system.install
```

Categories are dotted: `category.subcategory.verb`. The category captures *what kind of capability* (communication, credentials, filesystem, payment, memory, system, and so on). The subcategory and verb capture *the specific action*. A policy can match a single class (`forbid payment.transfer`) or, with Cedar, a set (`action in [filesystem.write, filesystem.delete]`).

The provider-oriented extensions (GitHub, Stripe, Gmail, Google Calendar) cover
actions that do not map cleanly onto the FEP base, such as GitHub's
`repo.lifecycle`, Stripe's `payment.refund`, or `calendar.delete`. These have
their own semantic subtree but follow the same naming rule: still no transport,
still no service name in the identifier itself. The *provider* lives elsewhere
— see "Resources" below.

Calendar classes distinguish reading, creating, updating, and deleting events.
For example, a scheduling assistant may receive `calendar.read` and
`calendar.create` while `calendar.update` and `calendar.delete` remain denied.
This prevents a capability for finding availability from silently becoming a
capability to cancel or rewrite existing meetings.

Some classes carry escalation channels a policy author should price in:

- `communication.external.filter` covers mail-filter management, and a Gmail
  filter can forward matching inbound mail to an external address. Granting
  the class permits setting up that forwarding even when
  `communication.external.send` is denied. Tools that emit messages
  themselves (for example a vacation auto-responder with an arbitrary body)
  are classified `communication.external.send`, not `filter`.
- `calendar.create` can email invites with arbitrary description text to
  arbitrary external attendees, so it is an outbound channel even without
  any `communication.external.*` grant.

## How a request becomes a class

The Sidecar's normalizer holds a **mapping table** loaded from TOML at startup. Each entry binds a `(method, host, path)` tuple to an action class:

```toml
[[rules]]
method       = "POST"
host         = "api.stripe.com"
path         = "/v1/payment_intents"
action_class = "payment.transfer"

[[rules]]
method       = "GET"
host         = "wttr.in"
path         = "*"
action_class = "communication.external.send"
```

`path` may be exact, may contain `*` wildcards, and `host` may use leading wildcards (`*.anthropic.com`). The lookup is deterministic: the first matching rule wins, and tie-breaking is left-to-right specificity.

OpenFirma ships four provider mapping files under
`crates/firma-sidecar/config/mappings/`:

| File            | Covers                                                      |
| --------------- | ----------------------------------------------------------- |
| `github.toml`   | GitHub REST + smart HTTP → 12 action classes                |
| `stripe.toml`   | 88 Stripe REST endpoints → 14 action classes                |
| `gmail.toml`    | 41 Gmail REST endpoints → 7 action classes                  |
| `composio.toml` | Composio execution transports and hosted MCP → 1 host class |

`composio.toml` is coarse on purpose: every Composio tool shares the same
handful of URLs, so the per-tool class comes from the pinned catalogs the
[Composio guide](../../guides/composio/) describes, not from the path.

You compose them, plus any project-specific rules, in `firma.toml`:

```toml
[sidecar.mapping]
rules_path = "config/mappings/default.toml"
rules_paths = [
  "crates/firma-sidecar/config/mappings/github.toml",
  "crates/firma-sidecar/config/mappings/stripe.toml",
]
default_protected = true
```

`default_protected = true` means **a request that matches no rule is treated as a protected action with no class assigned** — and because the pipeline is fail-closed, that is a DENY. Set it to `false` only when you explicitly want unmapped traffic to pass through (the bundled demo does this).

For a hands-on walkthrough of writing your own rules, see [Extend the action-class mapping](../../guides/extend-mapping/).

### GitHub smart HTTP

GitHub HTTPS git uses smart-HTTP endpoints on `github.com`, not the REST API host:

```toml
[[rules]]
method       = "POST"
host         = "github.com"
path         = "/*/*.git/git-receive-pack"
action_class = "code.write"
```

`git clone` and `git fetch` use `git-upload-pack` and map to `code.read`. `git push` uses `git-receive-pack` and maps to `code.write`; if the receive-pack body deletes a ref, the normalizer promotes the action to `code.destructive`. GitHub accepts both `https://github.com/owner/repo` and `https://github.com/owner/repo.git`; the shipped mapping covers both smart-HTTP path forms.

A receive-pack request must update exactly one ref. The Sidecar denies multi-ref
pushes because policy context contains one `git_ref`; split those updates into
separate pushes so every ref is evaluated.

These rules require HTTPS MITM for `github.com`. In CONNECT-only mode the Sidecar only sees `CONNECT github.com`, so branch/ref enforcement and git credential injection are not available.

## Resources: the other half of the picture

A class tells the policy *what kind of action*. The **resource** tells the policy *what it's acting on*. The Sidecar attaches a resource to every envelope as a small key-value map:

```text
host:     "api.github.com"
path:     "/repos/octocat/hello-world/issues"
provider: "github"
```

`host` and `path` are always present. `provider` is set only when the request host **exact-matches a known allowlist**:

| Host pattern                    | `provider` |
| ------------------------------- | ---------- |
| `api.github.com` / `github.com` | `github`   |
| `api.stripe.com`                | `stripe`   |
| `gmail.googleapis.com`          | `gmail`    |
| `app.composio.dev`              | `composio` |
| `backend.composio.dev`          | `composio` |

This split is intentional. Identifying the provider lets policies write rules like "no Stripe transfers above a threshold" without binding the rule to a specific URL path. Not setting it for unknown hosts keeps the namespace honest — the Sidecar refuses to guess.

In Cedar, the resource shows up as a `Firma::Resource::"<host><path>"` UID:

```cedar
forbid (
    principal,
    action == Firma::Action::"communication.external.send",
    resource == Firma::Resource::"paste.rs/"
);
```

## Where to go next

- [Capabilities](../capabilities/) — how a token authorizes a specific `action_class` + `resource_scope` for an agent.
- [Policies](../policies/) — how to write Cedar rules in terms of classes and resources.
- [Extend the action-class mapping](../../guides/extend-mapping/) — add a new SaaS provider without forking.
