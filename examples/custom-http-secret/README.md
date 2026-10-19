# Custom HTTP secret provider

This example registers a local mock web server as a full custom HTTP secret
provider. The server returns a fixed JSON secret, while the process inside
`firma run` receives only an `fsp_...` placeholder.

The client then sends that placeholder to the mock's echo endpoint. The Sidecar
rehydrates it before dispatch, the mock records the plaintext request on the
host, and the Sidecar masks the echoed response before it reaches the client.
No built-in integration or external vault is used.

## Requirements

- Linux with `bwrap` available
- Rust and Cargo
- Bash, Python 3, and curl

## Run

From the OpenFirma repository root:

```bash
./examples/custom-http-secret/run.sh
```

The sandboxed client knows only the expected placeholder shape. After it exits,
the host runner checks the fixed plaintext and exits successfully only when:

- the initial vault response contains a placeholder and no plaintext;
- the echoed response still contains no plaintext; and
- the host-local mock received the rehydrated fixed value
  (`local-http-secret`).

## Files

- `firma.toml` defines the full custom HTTP integration and its path rules.
- `mock_server.py` is the local mock vault.
- `client.sh` runs inside the sandbox and verifies redaction and masking.
- `run.sh` manages the mock server, Firma, assertions, and cleanup.

Plain HTTP is deliberate here: the goal is to demonstrate secret mediation
against a loopback mock without adding local certificate setup. Production HTTP
vaults should use HTTPS interception as documented in the secret gateway guide.
The fixed value is test data, not a real credential.
