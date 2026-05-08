# Before Firma: three separate control surfaces

This folder shows what teams often have before a system like Firma: several unrelated control files that all try to describe what an agent may do.

The intended rule is simple: the agent may read, but it must not write or destroy. In practice, that rule is split across provider-specific files:

| File | Surface | Vocabulary |
| --- | --- | --- |
| `oauth-scopes.json` | Gmail OAuth scopes | Google scope URIs |
| `github-token-permissions.yaml` | GitHub token permissions | GitHub PAT permissions |
| `network-allowlist.yaml` | Network egress | Hostnames |

Each file speaks a different language. None of them gives a shared answer to the question: what is the agent trying to do?

## The gap

The Gmail scope can block sending mail. The GitHub token can be read-only. The network allowlist can permit an internal host.

But once the host is allowed, the network layer does not understand whether the agent is reading a harmless endpoint or calling `DELETE /users/42`. The policy is fragmented, and the gaps appear between systems.

Firma closes that gap by evaluating a normalized action, not a provider-specific permission string or a hostname alone.
