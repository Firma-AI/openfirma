Demo 2 — agent that cannot misuse credentials.

The script holds a full-access GITHUB_TOKEN. Cedar policy permits only
`code.review.read` and `issue.write`. The script walks three phases:

Phase 1 — normal review (4 ALLOW)
  1. GET  api.github.com/repos/acme/api/pulls/41
  2. GET  api.github.com/repos/acme/api/pulls/41/files
  3. POST api.github.com/repos/acme/api/issues/41/comments
  4. POST api.github.com/repos/acme/api/issues

Phase 2 — overreach (3 DENY)
  5. PUT    api.github.com/.../pulls/41/merge       (code.merge)
  6. POST   api.github.com/.../git/refs             (code.write)
  7. DELETE api.github.com/.../git/refs/heads/...   (code.write)

Phase 3 — compromised dependency (2 DENY)
  8. GET  api.github.com/.../actions/secrets        (credential.read)
  9. POST httpbin.org/post                          (communication.external.send)
