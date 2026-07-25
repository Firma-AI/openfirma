# Contributing to OpenFirma

Thank you for your interest in contributing to OpenFirma! We'd love to have you contribute. Here are some resources and guidance to help you get started.

- [Getting Started](#getting-started)
- [Issues](#issues)
- [Pull Requests](#pull-requests)

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

If you find a bug, please create an issue and we'll triage it.

- Please search [existing issues](https://github.com/firma-ai/openfirma/issues) before creating a new one.
- Please include a clear description of the problem along with steps to reproduce it. Logs from `firma doctor` and `firma monitor` really help.

## Pull Requests

We actively welcome your Pull Requests! A couple of things to keep in mind before you submit:

- If you're fixing an issue, make sure someone else hasn't already created a PR fixing the same issue. Link your PR to the related issue(s).
- If you're new, we encourage you to take a look at issues tagged with [good first issue](https://github.com/firma-ai/openfirma/labels/good%20first%20issue).
- If you're submitting a new feature, please open an [issue](https://github.com/firma-ai/openfirma/issues/new) first to discuss it before opening a PR.

PR titles must use `type(scope)!: description`. The scope and breaking `!`
marker are optional. Accepted types are `ai`, `build`, `chore`, `ci`, `docs`,
`feat`, `fix`, `perf`, `refactor`, `revert`, `security`, and `test`.

Release notes are generated from PR titles. `ai`, `build`, `chore`, `ci`,
`refactor`, and `test` PRs are excluded. Those types cannot use `!` because a
public breaking change must not be hidden.

Before submitting your PR, please run these checks locally:

```bash
just check     # fmt + lint + test + build + audit + dependency check
```

Running this before you create the PR will help reduce back and forth during review.

## License

By contributing to OpenFirma, you agree that your contributions will be licensed under the [GPL License 3.0](LICENSE).
