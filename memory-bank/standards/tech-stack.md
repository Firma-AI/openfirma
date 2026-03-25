# Tech Stack

## Overview

Firma OSS is a Rust-based security sidecar and policy enforcement system for AI agents. The stack is optimized for sub-millisecond latency, transparent HTTP proxy interception, and Cedar policy evaluation — deployed in OSS V1 as two cooperating binaries (`firma-sidecar` and `firma-authority`) running locally, in Docker, or in Kubernetes.

## Languages

Rust

Performance-critical proxy with strict latency requirements (<1ms p95 Stage 1, <200µs p95 Stage 2). Rust provides memory safety without garbage collection, predictable latency, and a strong type system for security-critical code. Precedent: Linkerd2-proxy proves Rust sidecar proxies at production scale.

## Framework

Axum + Hyper + Tonic (Tower middleware ecosystem)

- **Axum** — HTTP routing, request/response interception via Tower middleware, forward proxy handling. Official http-proxy example supports CONNECT tunneling.
- **Hyper** — Raw HTTP connection lifecycle for CONNECT/MITM upgrade path. Axum is built on Hyper, so they compose naturally.
- **Tonic** — gRPC client for Authority communication (IssueCapability, WatchPolicyBundle, WatchRevocations streaming RPCs). Co-hosted with Axum on same Hyper server via content-type routing.
- **Tower** — Middleware composition shared across Axum and Tonic. Request/response body inspection, audit emission, credential injection as Tower layers.

Why this stack: Linkerd2-proxy validates this architecture at scale. Pingora (Cloudflare) appears better aligned with streaming reverse-proxy workloads than with Firma's interception-heavy sidecar needs: body filters are chunk-oriented, full-response buffering is not a first-class abstraction, response body filters remain synchronous, and forward-proxy/CONNECT support is less mature. Actix-web lacks Tower/Tonic interop. Rama is too immature (pre-1.0).

## TLS & Crypto

- **rustls** — TLS implementation (no OpenSSL dependency, pure Rust)
- **rcgen** — Dynamic certificate generation for MITM HTTPS interception
- **tokio-rustls** — Async TLS integration

## Policy & Token

- **cedar-policy** — Cedar policy evaluation engine (4-11µs median eval time)
- **rusty_paseto** — PASETO v4 token validation (preferred token format)
- **jsonwebtoken** — JWT RS256 validation (fallback token format)

## Async Runtime

Tokio

Shared runtime across Axum, Tonic, and Hyper. Each agent connection is a Tokio task. Enables concurrent handling of multiple agent sessions.

## Authentication

Authentication is required at the Authority boundary. Capability tokens identify an agent after issuance, but they do not replace bootstrap authentication for `IssueCapability`.

OSS V1 requires authenticated callers for Authority RPCs, but does not standardize a single bootstrap mechanism in the wire contract yet. Common deployments may enforce this with local-only networking, a reverse proxy, or mTLS.

## Infrastructure & Deployment

Layered adoption funnel (local process pair → Docker → Kubernetes):

- **Tier 1 — Try it**: Run `firma-sidecar` and `firma-authority` as two local processes with file-based Cedar policies. Zero external dependencies. Target: under 5 minutes to first policy enforcement.
- **Tier 2 — Evaluate it**: Docker images (GHCR + Docker Hub) with `docker-compose.yml` example showing sample AI agent + Sidecar + Mini Authority + mock tool endpoint.
- **Tier 3 — Run it**: Helm chart with sidecar injection support for Kubernetes production deployments, with Authority deployed as a separate service.

Distribution channels (prioritized):

1. GitHub Releases with pre-built `firma-sidecar` and `firma-authority` binaries (Linux x86_64/aarch64, macOS x86_64/aarch64) via cargo-dist
2. Docker images on GHCR and Docker Hub
3. One-line install script
4. crates.io with cargo-binstall metadata
5. Homebrew tap
6. Helm chart
7. Signed releases (cosign/Sigstore) + SBOMs

## Package Manager

Cargo

## Key Crate Dependencies

```toml
# Core HTTP proxy
axum = "0.8"
hyper = { version = "1", features = ["full"] }
hyper-util = { version = "0.1", features = ["full"] }
http-body-util = "0.1"

# gRPC
tonic = "0.13"
prost = "0.13"

# TLS interception (MITM)
rustls = "0.23"
rcgen = "0.13"
tokio-rustls = "0.26"

# Async runtime
tokio = { version = "1", features = ["full"] }
tower = "0.5"

# Policy evaluation
cedar-policy = "4"

# Token validation
rusty_paseto = "0.7"
jsonwebtoken = "9"
```

## Decision Relationships

- Framework choice (Axum/Hyper/Tonic) supports the compact two-binary OSS architecture without requiring separate gateway processes
- rustls + rcgen enables transparent HTTPS interception without OpenSSL dependency, simplifying static binary distribution
- Cedar policy engine is the same engine used by AWS Verified Permissions — strong formal verification properties for security-critical eval
- Tower middleware ecosystem is shared across all framework components, enabling consistent request/response interception patterns
