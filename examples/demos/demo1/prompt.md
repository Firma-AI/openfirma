Demo 1b — same host, different path.

The script will issue two calls to the same host:

1. GET httpbin.org/get?user=user-123 (filesystem.read)
2. GET httpbin.org/anything/billing?user=user-123 (credential.read)

Cedar policy permits only `filesystem.read`.
Watch the audit pane: ALLOW for /usage, DENY for /billing —
decision made on the canonical action class, not on the host.
