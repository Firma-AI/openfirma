# Tech Stack

## Overview

Firma OSS is a Rust-based security sidecar and policy enforcement system for AI agents. Deployed in OSS V1 as two cooperating binaries (`firma-sidecar` and `firma-authority`) running locally, in Docker, or in Kubernetes.

## Languages

Rust

Performance-critical proxy with strict latency requirements. Rust provides memory safety without garbage collection, predictable latency, and a strong type system for security-critical code.

## Framework

Pingora + Tonic + Tower

- **Pingora** — HTTP proxy engine for `firma-sidecar`. Purpose-built lifecycle hooks for request/response interception.
- **Tonic** — gRPC for Authority communication. Also the preferred path for any gRPC-based tool execution interception.
- **Tower** — Composable `Service`/`Layer` pipeline shared across Pingora and Tonic for cross-cutting concerns.

## TLS & Crypto

- **rustls** — TLS implementation (no OpenSSL dependency, pure Rust)
- **rcgen** — Dynamic certificate generation for MITM HTTPS interception
- **tokio-rustls** — Async TLS integration

## Policy & Token

- **cedar-policy** — Cedar policy evaluation engine
- **rusty_paseto** — PASETO v4 token validation (preferred token format)
- **jsonwebtoken** — JWT RS256 validation (fallback token format)

## Async Runtime

Tokio

Shared runtime across Pingora, Tonic, and Tower. Each agent connection is a Tokio task.

## Authentication

Authentication is required at the Authority boundary. Capability tokens identify an agent after issuance, but they do not replace bootstrap authentication for capability issuance.

OSS V1 requires authenticated callers for Authority RPCs, but does not standardize a single bootstrap mechanism in the wire contract yet.

## Infrastructure & Deployment

Layered adoption funnel (local process pair → Docker → Kubernetes):

- **Tier 1 — Try it**: Run `firma-sidecar` and `firma-authority` as two local processes with file-based Cedar policies. Zero external dependencies. Target: under 5 minutes to first policy enforcement.
- **Tier 2 — Evaluate it**: Docker images (GHCR + Docker Hub) with `docker-compose.yml` example.
- **Tier 3 — Run it**: Helm chart with sidecar injection support for Kubernetes production deployments.

Distribution channels (prioritized):

1. GitHub Releases with pre-built binaries (Linux x86_64/aarch64, macOS x86_64/aarch64) via cargo-dist
2. Docker images on GHCR and Docker Hub
3. One-line install script
4. crates.io with cargo-binstall metadata
5. Homebrew tap
6. Helm chart
7. Signed releases (cosign/Sigstore) + SBOMs

## Package Manager

Cargo
