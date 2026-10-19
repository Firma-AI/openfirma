# Custom CLI secret provider

This example registers a local mock CLI as a full custom secret provider. The
mock returns a fixed JSON secret, while the process inside `firma run` receives
only an `fsp_...` placeholder.

No built-in integration or external vault is used.

## Requirements

- Linux on x86-64 or ARM64, with a GNU or musl Rust host toolchain and `bwrap`
  available
- Rust and Cargo
- Bash

## Run

From the OpenFirma repository root:

```bash
./examples/custom-cli-secret/run.sh
```

The runner builds `firma`, builds a static private secret shim for the current
Linux host target, stages it in OpenFirma's target-qualified development layout,
puts the mock CLI on the host `PATH`, and launches `client.sh` inside the
sandbox. The sandboxed client requires a placeholder; after it exits, the host
runner fails if captured client output contains the fixed plaintext
(`local-cli-secret`).

## Files

- `firma.toml` defines the full custom CLI integration and its command rules.
- `mock-secret-cli` is the local mock vault executable.
- `client.sh` runs inside the sandbox and verifies the redacted response.
- `run.sh` prepares local state and runs the example.

The fixed value is test data, not a real credential. This example is for local
development only.
