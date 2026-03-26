# System Architecture

## Overview

Firma OSS follows a sidecar proxy architecture. The system is split into two binaries (`firma-sidecar` + `firma-authority`) communicating via gRPC, with all enforcement happening locally in the Sidecar — no hot-path network calls.

OSS V1 deploys these as separate local processes or services. Docker and Kubernetes package the same split architecture rather than embedding the Authority into the Sidecar.

## Architecture Style

**Sidecar proxy pattern** with local enforcement

The Sidecar runs as a co-located process alongside each AI agent. All agent outbound traffic routes through the Sidecar. The Sidecar evaluates every request locally before forwarding to the target.

```text
┌─────────────────────────────────────────────────────────┐
│  Agent Host / Container                                 │
│                                                         │
│  ┌──────────┐    HTTP_PROXY     ┌────────────────────┐  │
│  │ AI Agent │ ───────────────── │   Firma Sidecar    │  │
│  └──────────┘                   │  (enforcement)     │  │
│                                 └────────┬───────────┘  │
│                                          │ gRPC         │
│                                          ▼              │
│                                 ┌────────────────────┐  │
│                                 │  Mini Authority    │  │
│                                 │  (policy + tokens) │  │
│                                 └────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

**Key invariant**: Authority is contacted only during pre-flight (capability issuance). Enforcement is fully local — no network calls on the hot path.

## Workspace Crates

| Crate | Type | Responsibility |
| ------- | ------ | ---------------- |
| `firma-sidecar` | Binary | HTTP proxy, enforcement pipeline, audit, credential injection |
| `firma-authority` | Binary | Mini Authority — policy loading, capability issuance, gRPC streams |
| `firma-core` | Library | Shared types, capability tokens, Cedar wrapper, error types |
| `firma-proto` | Library | Protobuf/gRPC service definitions, generated code |
