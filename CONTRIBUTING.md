# Contributing to OpenFirma

Thank you for your interest in contributing to OpenFirma.

- [Getting Started](#getting-started)
- [Issues](#issues)
- [Contributing changes](#contributing-changes)

## Getting Started

To ensure a positive and inclusive environment, please read our [Code of Conduct](CODE_OF_CONDUCT.md) before contributing.

### Local Development Setup

```bash
git clone https://github.com/firma-ai/openfirma.git
cd openfirma
just install
```

Install `just` first (`brew install just` on macOS, `cargo binstall just` elsewhere after installing `cargo-binstall`, or your distro package), then run `just install` to set up everything else: Rust toolchain check, protoc, cargo tools, and docs dependencies. See the [README](README.md) for more details on prerequisites and configuration.

## Issues

If you find a bug or want to propose a feature, please create an issue and
we'll triage it.

- Please search [existing issues](https://github.com/firma-ai/openfirma/issues) before creating a new one.
- Please include a clear description of the problem along with steps to reproduce it. Logs from `firma doctor` and `firma monitor` really help.
- Report security vulnerabilities through the process in [SECURITY.md](SECURITY.md), not through a public issue.

## Contributing changes

Pull requests are disabled. Start with a public issue describing the motivation,
expected behavior, and any relevant reproduction. Maintainers will coordinate
accepted changes.

When investigating or validating a proposed change locally, run:

```bash
just check     # fmt + lint + test + build + audit + dependency check
just hawk      # unnecessary public API visibility (macOS and Linux)
```

## License

By contributing to OpenFirma, you agree that your contributions will be licensed under the [GPL License 3.0](LICENSE).
