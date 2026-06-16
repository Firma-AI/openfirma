Demo 0 — fragmented enforcement, one rule.

The script will issue three calls in order:

1. GET api.github.com/repos/acme/api/pulls/41 (code.review.read)
2. POST gmail.googleapis.com/.../messages/send (communication.external.send)
3. DELETE httpbin.org/delete (account.permission.change)

Cedar policy permits only `code.review.read` and `filesystem.read`.
Watch the audit pane: 1 ALLOW, 2 DENY.
