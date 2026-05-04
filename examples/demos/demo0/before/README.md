# Before Firma — three governance surfaces

These are the three artifacts a team would hand-roll today to express the rule
"the agent can read but cannot write or destroy" against three providers.

| File | Surface | Provider | Vocabulary |
|---|---|---|---|
| `oauth-scopes.json` | OAuth scopes | Gmail | Google scope URIs |
| `github-token-permissions.yaml` | Token permissions | GitHub | GitHub PAT permission set |
| `network-allowlist.yaml` | Network allowlist | Internal service | Hostnames |

Three vocabularies. Zero shared representation of "what the agent is doing".

## The gap

The Gmail scope blocks `gmail.send`. The GitHub PAT has only read permissions.
The network allowlist permits the internal service host — **and that is all it
permits at**. Once the host is on the list, every HTTP method to every path on
that host is allowed to leave the agent's network. A `DELETE /users/42` to the
internal service goes through.

The rule was consistent. The three surfaces were not. That is the gap Firma
closes by replacing all three with a single Cedar policy evaluated against a
canonical action class taxonomy.
