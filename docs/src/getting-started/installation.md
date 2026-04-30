# Installation

## Prerequisites

- **Rust 1.80 or later** — install via [rustup](https://rustup.rs/).
- **`protoc` 3.15 or later** — the Protocol Buffers compiler, required for
  `firma-proto` compilation. Install via your system package manager
  (`apt install protobuf-compiler`, `brew install protobuf`, etc.).
- OS-specific requirements for `firma-run` sandbox backends:
  - **Linux** — `bwrap` (bubblewrap) for structural confinement.
  - **macOS** — macOS 13 (Ventura) or later for Apple Virtualization.framework.
  - **Windows** — WSL2 enabled (Windows 10 build 19041 or later).

## From source (recommended for v0)

```bash
git clone https://github.com/Firma-AI/firma-oss
cd firma-oss
make build
```

After a successful build you will find the binaries at:

- `target/debug/firma-sidecar`
- `target/debug/firma-authority`

For a release build:

```bash
cargo build --release --workspace
```

## Demo (quick verification)

```bash
make demo-ci
```

Expected output:

```text
[allow] 200 OK path=/allow body={"ok":true,"path":"/allow"}
[deny] 403 Forbidden path=/deny body={"denied":true,"reason":"...","detail":"..."}
[ok] ALLOW + DENY round-trips matched expectation.
```

The demo requires no cloud dependencies and no API keys. It boots a local
Authority and Sidecar, pre-issues a capability, and exercises one ALLOW and one
DENY path end-to-end.

## Verifying the install

```bash
./target/debug/firma-sidecar --help
./target/debug/firma-authority --help
```

Both commands should print their usage text and exit `0`.

## Where next

Continue to [Quick Start](./quick-start.md) to boot the stack step by step and
send your first enforced request.
