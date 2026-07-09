# FIR-413 Git Demo

This demo exercises GitHub HTTPS git enforcement through the Firma sidecar. It
uses Git smart-HTTP over MITM, injects a GitHub PAT from the sidecar, and checks:

- clone/fetch traffic is allowed as `code.read`
- push to `refs/heads/firma-git-demo-allowed` is allowed as `code.write`
- push to `refs/heads/main` is denied by Cedar
- branch deletion is classified as `code.destructive` and denied

Required environment:

```bash
export FIRMA_GIT_DEMO_GITHUB_TOKEN="..."
export FIRMA_GIT_DEMO_REPO="owner/repo"
```

`FIRMA_GIT_DEMO_GITHUB_TOKEN` should be a PAT with read/write contents access to
the disposable test repository. `FIRMA_GIT_DEMO_REPO` is not secret and should be
configured as a GitHub Actions variable when running in CI.

Run:

```bash
just git-demo-ci
```

If either variable is missing, the demo exits successfully with a skip message.
