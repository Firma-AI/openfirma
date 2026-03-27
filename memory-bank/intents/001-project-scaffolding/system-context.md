---
intent: 001-project-scaffolding
phase: inception
status: context-defined
updated: 2026-03-26T10:15:00Z
---

# Project Scaffolding - System Context

## System Overview

This intent establishes the Cargo workspace structure for Firma OSS. No runtime behavior — purely project setup, build tooling, and CI configuration.

## Context Diagram

```mermaid
C4Context
    title System Context - Project Scaffolding

    Person(dev, "Developer", "Team of 3 building Firma OSS")
    System(workspace, "Firma Workspace", "Cargo workspace with 4 crates")
    System_Ext(gh, "GitHub Actions", "CI/CD pipeline")
    System_Ext(crates_io, "crates.io", "Rust dependency registry")

    Rel(dev, workspace, "Develops, runs make check")
    Rel(workspace, gh, "Push triggers CI")
    Rel(workspace, crates_io, "Downloads dependencies")
```

## External Integrations

- **GitHub Actions**: CI pipeline triggered on push/PR — runs fmt, clippy, test, build
- **crates.io**: Dependency resolution for tokio, tracing (minimal deps at this stage)

## High-Level Constraints

- Must compile offline after initial dependency fetch
- No runtime services or external APIs
- Rust stable toolchain only
