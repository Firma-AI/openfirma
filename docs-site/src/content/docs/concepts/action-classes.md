---
title: Action classes
description: The canonical vocabulary that connects raw HTTP traffic to the policies that govern it.
---

A capability says "this agent may perform `communication.external.send`". A policy says "`payment.transfer` is forbidden over this amount". Neither statement mentions an HTTP method, a host, or a path. They are written in terms of **action classes**, the shared vocabulary that the rest of OpenFirma speaks.

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

OpenFirma ships with **44 canonical action classes**. The base 15 come from **FEP v0.1**, the versioned Firma protocol specification that defines the canonical registry and its invariants. The remaining classes extend that base for GitHub (12), Stripe (12), and Gmail (5). The full list lives in `docs/markdown/firma_action_class_registry.md` in the repository.

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

The provider-specific extensions (GitHub, Stripe, Gmail) cover endpoints that don't map cleanly onto the FEP base — for example, GitHub's `repo.lifecycle` or Stripe's `payment.refund`. These have their own subtree but follow the same naming rule: still no transport, still no service name in the identifier itself. The *provider* lives elsewhere — see "Resources" below.

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

OpenFirma ships three default mapping files under `crates/firma-sidecar/config/mappings/`:

| File          | Covers                                       |
| ------------- | -------------------------------------------- |
| `github.toml` | 44 GitHub REST endpoints → 12 action classes |
| `stripe.toml` | 88 Stripe REST endpoints → 14 action classes |
| `gmail.toml`  | 41 Gmail REST endpoints → 7 action classes   |

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

## Resources: the other half of the picture

A class tells the policy *what kind of action*. The **resource** tells the policy *what it's acting on*. The Sidecar attaches a resource to every envelope as a small key-value map:

```text
host:     "api.github.com"
path:     "/repos/octocat/hello-world/issues"
provider: "github"
```

`host` and `path` are always present. `provider` is set only when the request host **exact-matches a known allowlist**:

| Host pattern                            | `provider` |
| --------------------------------------- | ---------- |
| `api.github.com` / `github.com`         | `github`   |
| `api.stripe.com`                        | `stripe`   |
| `gmail.googleapis.com`                  | `gmail`    |

This split is intentional. Identifying the provider lets policies write rules like "no Stripe transfers above a threshold" without binding the rule to a specific URL path. Not setting it for unknown hosts keeps the namespace honest — the Sidecar refuses to guess.

In Cedar, the resource shows up as a `Firma::Resource::"<host><path>"` UID:

```cedar
forbid (
    principal,
    action == Firma::Action::"communication.external.send",
    resource == Firma::Resource::"paste.rs/"
);
```

(Note `paste.rs/` — the trailing slash is the normalizer's representation of an empty path. This is a real source of subtle policy bugs; see the comments in `examples/demo/policies/example-deny.cedar`.)

## What action classes are *not*

A few common misunderstandings worth heading off:

- **They are not authentication.** A class identifies *what* an agent is trying to do; whether the agent is *allowed* to do it is decided by capability (Stage 1) and policy (Stage 2). The class itself is morally neutral.
- **They are not unique to a host.** `communication.external.send` covers paste.rs *and* webhooks *and* arbitrary POSTs to unknown hosts. The class is the *category* of behavior. The resource (host+path) is what differentiates instances.
- **They are not extensible at runtime.** You add a class by editing the registry, recompiling the Sidecar, and shipping a new mapping file. There is intentionally no plugin or remote-config path. Determinism is the feature.
- **They do not carry secrets.** Headers, cookies, body content — none of this is part of the class or the resource. The Sidecar strips sensitive headers before normalization to ensure they don't leak into audit logs.

## Where to go next

- [Capabilities](../capabilities/) — how a token authorizes a specific `action_class` + `resource_scope` for an agent.
- [Policies](../policies/) — how to write Cedar rules in terms of classes and resources.
- [Extend the action-class mapping](../../guides/extend-mapping/) — add a new SaaS provider without forking.
