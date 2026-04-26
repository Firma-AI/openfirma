---
intent: 007-firma-run-sandbox-launcher
phase: inception
status: context-defined
updated: 2026-04-26T12:00:00Z
---

# Firma Run Sandbox Launcher - System Context

## System Overview

`firma-run` is a wrapper runtime that launches an agent process inside a sandbox and enforces that outbound traffic is mediated by `firma-sidecar`. FIR-61 implementation scope is Linux-first (`bwrap` backend) with a pluggable backend contract for future FIR-60 matrix completion.

The control objective is structural mediation, not cooperative behavior. Agent traffic must be sidecar-mediated or blocked.

## Context Diagram

```mermaid
flowchart LR
    subgraph host[Host Linux]
        fr[firma-run orchestrator]
        sc[firma-sidecar]
        uds[/run/firma-sidecar/<sandbox_id>.sock]
        fr --> sc
        sc --- uds
    end

    subgraph ns[bwrap network namespace]
        agent[agent process\npython/node/codex/etc.]
        proxy[local egress bridge\n127.0.0.1:18080]
        dns[dns stub\n127.0.0.1:53]
        agent --> proxy
        agent --> dns
    end

    proxy --> uds
    dns --> uds

    sc --> ext[External HTTP APIs]
    sc --> auth[Firma Authority streams]
```

## Derek Scheme Mapping

The proposed Derek flow is adopted with one explicit bridge detail:

- **Inside sandbox**: agent only talks to sandbox-local bridge (`127.0.0.1`) and DNS stub.
- **Cross-boundary path**: bridge forwards to sidecar Unix socket (`/run/firma-sidecar.sock`-class path).
- **Enforcement plane**: sidecar remains the single policy plane.

This keeps the sidecar as the only egress path while avoiding trust in direct `HTTP_PROXY` cooperation.

## External Integrations

- **firma-sidecar**: mandatory mediation endpoint for all successful outbound HTTP traffic.
- **Firma Authority**: policy/revocation/capability control-plane dependencies remain sidecar/authority concerns.
- **bubblewrap + Linux namespace primitives**: runtime sandbox substrate for FIR-61.

## High-Level Constraints

- Linux-only implementation in FIR-61.
- No second policy plane.
- Sidecar unavailable => fail-closed network behavior.
- DNS path must be explicit and controlled.

## Key NFR Goals

- Preserve interactive CLI/TUI behavior.
- Keep startup and mediation overhead measurable and within launch budgets.
- Provide deterministic audit attribution for concurrent sandboxed runs.
