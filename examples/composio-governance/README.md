# Composio governance demo

This credential-free demo runs OpenFirma against a local TLS upstream. It uses
a pinned in-memory Gmail catalog and never contacts Composio.

Run it from the repository root:

```bash
./examples/composio-governance/run.sh
```

The automated scenario proves:

- an allowed tool execution reaches the mock TLS upstream once;
- a denied execution reaches it zero times;
- a mixed allow/deny multi-tool batch is blocked atomically;
- monitor mode forwards the original request once and retains the would-deny
  audit reason.

The test uses synthetic user and account selectors and empty tool arguments. It
requires no API key, OAuth token, or connected account.
