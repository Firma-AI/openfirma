# Data Stack

## Overview

Firma OSS has no external database dependency. All state is file-based (policies, config) or in-memory (sessions, bloom filters, policy cache). Audit events emit to stdout or file in OSS V1. Storage traits allow the enterprise version to plug in persistent backends.

## Database

None

The OSS version is designed for zero-infrastructure operation. Cedar policies are loaded from `.cedar` files on disk. Capability tokens are issued and validated in-memory. Session state lives in-process. This aligns with the "5-minute quickstart" adoption goal — no database to provision.

## In-Memory State

- **Policy bundle**: Cedar policy set compiled from `.cedar` files, refreshed via WatchPolicyBundle
- **Bloom filter**: Revoked token IDs, updated via WatchRevocations stream
- **Session map**: Active agent sessions with their capability tokens
- **Budget counters**: Per-capability budget tracking (in-process, not persisted)

## File-Based Storage

- **Cedar policies**: `.cedar` files in a configurable directory
- **Entity schema**: Cedar entity schema for policy validation
- **Configuration**: TOML config files for sidecar and Mini Authority settings
- **Audit log**: Structured JSON lines to file (optional, default is stdout)

## Storage Abstraction

Define Rust traits for storage boundaries so the enterprise version can substitute persistent backends:

- `PolicyStore` trait — file-based for OSS, remote bundle service for enterprise
- `AuditSink` trait — stdout/file for OSS V1, remote stream or database for enterprise
- `RevocationStore` trait — bloom filter for OSS, distributed cache for enterprise
- `CredentialStore` trait — file-based secrets for OSS, vault integration for enterprise

## Decision Relationships

- No database simplifies the zero-infrastructure local deployment model used by the OSS V1 Sidecar + Authority pair
- Storage traits at boundaries keep the architecture open for enterprise extensibility without coupling the OSS version to infrastructure it doesn't need
- Audit to stdout integrates naturally with container logging (Docker, Kubernetes)
