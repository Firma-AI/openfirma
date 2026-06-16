Demo 2 — compromised agent, credentials held by the sidecar.

The script appears to wield a full-access GITHUB_TOKEN, but scrubs it from
its own environment at startup. The sidecar holds the real token under
`[credentials.github]` and injects `Authorization: Bearer …` only after
an ALLOW decision. Cedar permits `code.review.read` and `issue.write`.

Pre-req: export GITHUB_TOKEN in the shell before launching `run.sh demo2`
so the sidecar can read it at boot. The agent process never sees it.

Phase 1 — normal review (4 ALLOW)

1. GET api.github.com/repos/acme/api/pulls/41
2. GET api.github.com/repos/acme/api/pulls/41/files
3. POST api.github.com/repos/acme/api/issues/41/comments
4. POST api.github.com/repos/acme/api/issues

Phase 2 — overreach (3 DENY)
5. PUT api.github.com/.../pulls/41/merge (code.merge)
6. POST api.github.com/.../git/refs (code.write)
7. DELETE api.github.com/.../git/refs/heads/... (code.write)

Phase 3 — compromised dependency (2 DENY)
8. GET api.github.com/.../actions/secrets (credential.read)
9. POST httpbin.org/post (communication.external.send)

Closing frame: "The perimeter is the call, not the agent."
