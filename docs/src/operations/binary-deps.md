# Binary Dependencies

## Runtime dependencies

The two OpenAuthority binaries have no OS-level runtime requirements beyond the
system C library. Both are statically linked Rust binaries.

| Binary            | Purpose                                                 | Runtime requirement             |
| ----------------- | ------------------------------------------------------- | ------------------------------- |
| `firma-sidecar`   | HTTP proxy + two-stage enforcement                      | None beyond libc (static build) |
| `firma-authority` | Capability issuance, policy bundles, revocation streams | None beyond libc (static build) |

### firma-run backend dependencies

The `firma-run` execution backends require OS-specific tooling that must be
present at runtime.

| Backend | OS      | Requirement                    | Notes                                                        |
| ------- | ------- | ------------------------------ | ------------------------------------------------------------ |
| `bwrap` | Linux   | bubblewrap (`bwrap` binary)    | Install: `apt install bubblewrap` / `dnf install bubblewrap` |
| `vz`    | macOS   | Apple Virtualization.framework | Requires macOS 13 (Ventura) or later                         |
| `wsl2`  | Windows | WSL2 enabled                   | Windows 10 build 19041+ or Windows 11                        |

## Build dependencies

Building from source requires:

- Rust toolchain 1.80 or later — install via `rustup` from <https://rustup.rs>
- `protoc` — Protocol Buffers compiler, required for `firma-proto` compilation.
  Install: `apt install protobuf-compiler` / `brew install protobuf` / download
  from `github.com/protocolbuffers/protobuf/releases`.
  proto3 optional field support requires `protoc` 3.15 or later.
- Cargo — included with the Rust toolchain.

## Verifying versions

Run the following commands to confirm required versions are installed:

```bash
rustc --version    # expect 1.80+
cargo --version
protoc --version   # expect libprotoc 3.15+
bwrap --version    # Linux only
```

## Distribution targets

OpenAuthority ships pre-built binaries for the following targets:

- Linux: `x86_64-unknown-linux-gnu` (glibc), `x86_64-unknown-linux-musl`
- macOS: `aarch64-apple-darwin` (Apple Silicon), `x86_64-apple-darwin`
- Windows: `x86_64-pc-windows-msvc`

musl builds are fully static and have no shared-library dependencies. glibc
builds link against the system libc and require glibc 2.17 or later.
