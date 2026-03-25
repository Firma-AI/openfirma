# Tech Stack

## Overview

Firma OSS is a Rust-based security sidecar and policy enforcement system for AI agents. The stack is optimized for sub-millisecond latency, transparent HTTP proxy interception, and Cedar policy evaluation — deployed in OSS V1 as two cooperating binaries (`firma-sidecar` and `firma-authority`) running locally, in Docker, or in Kubernetes.

## Languages

Rust

Performance-critical proxy with strict latency requirements (<1ms p95 Stage 1, <200µs p95 Stage 2). Rust provides memory safety without garbage collection, predictable latency, and a strong type system for security-critical code. Precedent: Linkerd2-proxy proves Rust sidecar proxies at production scale.

## Framework

Pingora + Tonic + Tower

- **Pingora** — HTTP proxy engine for `firma-sidecar`. `ProxyHttp` trait hooks map directly to enforcement phases: `request_filter()` for identity/provider detection, `upstream_request_filter()` for credential injection, `upstream_response_body_filter()` for LLM response parsing and Cedar evaluation. Chunk-oriented body filters are ideal for SSE event-level filtering (tool call events get Cedar eval; text events pass through at zero added latency). Synchronous filters are sufficient — Cedar eval is in-process, sub-millisecond. Proven at 40M+ req/s at Cloudflare.
- **Tonic** — gRPC for Authority communication (IssueCapability, WatchPolicyBundle, WatchRevocations). Also the preferred path for any gRPC-based tool execution interception.
- **Tower** — Composable `Service`/`Layer` pipeline shared across Pingora and Tonic for cross-cutting concerns (audit, credential injection).

Why Pingora over Axum/Hyper: The sidecar's critical path is LLM response inspection and tool call extraction — a response-inspecting proxy workload. Pingora's `ProxyHttp` trait provides purpose-built lifecycle hooks for this, vs. Axum/Hyper which require more custom plumbing for proxy-style response body interception. Actix-web lacks Tower/Tonic interop. Rama is pre-1.0.

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

Shared runtime across Pingora, Tonic, and Tower. Each agent connection is a Tokio task.

## Authentication

Authentication is required at the Authority boundary. Capability tokens identify an agent after issuance, but they do not replace bootstrap authentication for `IssueCapability`.

OSS V1 requires authenticated callers for Authority RPCs, but does not standardize a single bootstrap mechanism in the wire contract yet. Common deployments may enforce this with local-only networking, a reverse proxy, or mTLS.

## Infrastructure & Deployment

Layered adoption funnel (local process pair → Docker → Kubernetes):

- **Tier 1 — Try it**: Run `firma-sidecar` and `firma-authority` as two local processes with file-based Cedar policies. Zero external dependencies. Target: under 5 minutes to first policy enforcement.
- **Tier 2 — Evaluate it**: Docker images (GHCR + Docker Hub) with `docker-compose.yml` example showing sample AI agent + Sidecar + Mini Authority + mock tool endpoint.
- **Tier 3 — Run it**: Helm chart with sidecar injection support for Kubernetes production deployments, with Mini Authority deployed as a separate service.

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

## Decision Relationships

- Pingora for sidecar HTTP + Tonic for Authority gRPC supports the compact two-binary architecture without separate gateway processes
- rustls + rcgen enables transparent HTTPS interception without OpenSSL dependency, simplifying static binary distribution
- Cedar policy engine is the same engine used by AWS Verified Permissions — strong formal verification properties for security-critical eval
- Tower middleware ecosystem is shared across all framework components, enabling consistent request/response interception patterns
