# macOS VZ Codex PTY

This example is expected to evolve while the VZ guest backend is under active development.
Its job right now is to provide a way to boot the guest,
start the locked Linux Codex binary with the host terminal attached through the
guest PTY VSOCK path.

This example proves the following:

1. build and ad-hoc sign `firma-vz-runner`
2. build local guest artifacts
3. boot the linux guest
4. request a PTY launch through the `codex` profile
5. run `codex` with the host terminal attached to the guest PTY

## Run

```bash
just macos-vz-codex-pty
```

The example intentionally fails when stdin or stdout is not a TTY,
because `firma run` only requests PTY mode when it can capture host terminal state.

The command executed inside the guest is:

```bash
codex
```

The example uses an isolated Codex home by default:

```text
examples/firma-run/macos-vz-codex-pty/.runtime/codex-home
```

Override it when you want to reuse an existing Codex state directory that is
also visible inside the mounted repository:

```bash
FIRMA_VZ_CODEX_PTY_CODEX_HOME=<path> just macos-vz-codex-pty
```

For now if `OPENAI_API_KEY` is set on the host, the built-in `codex` profile passes it
through. Otherwise codex can use its normal interactive login flow.

Future work should move this away from raw host environment passthrough. The
guest should receive only explicit, accepted environment values or scoped
placeholder tokens, while real credentials stay on the host and are injected by
the Sidecar only after the request is allowed.

## Overrides

Build and use your own existing artifact directory:

```bash
FIRMA_VZ_CODEX_PTY_ARTIFACTS=target/firma-vz-guest/aarch64 just macos-vz-codex-pty
```

Use another known-good Kata kernel:

```bash
FIRMA_VZ_CODEX_PTY_KERNEL=/path/to/kata-vmlinux just macos-vz-codex-pty
```

Use a different example config:

```bash
FIRMA_VZ_CODEX_PTY_CONFIG=/path/to/firma.toml just macos-vz-codex-pty
```
