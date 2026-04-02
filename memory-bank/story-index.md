# Global Story Index

## Overview

- **Total stories**: 17
- **Complete**: 17
- **Planned**: 0
- **Last updated**: 2026-04-02

---

## Stories by Intent

### 001-project-scaffolding

#### Unit: 001-workspace-setup

- [x] **001-workspace-and-crates** (001-workspace-setup): Cargo workspace, 4 crates, dependency graph, stub entrypoints - Must - GENERATED
- [x] **002-clippy-and-fmt** (001-workspace-setup): Workspace-level Clippy lints and formatting config - Must - GENERATED
- [x] **003-ci-pipeline** (001-workspace-setup): GitHub Actions CI workflow - Must - GENERATED
- [x] **004-makefile** (001-workspace-setup): Makefile mirroring CI - Must - GENERATED

### 002-core-types-shared-library

#### Unit: 001-types-and-traits

- [x] **001-capability-token-types** (002-types-and-traits): CapabilityClaims struct, TokenState enum - Must - GENERATED
- [x] **002-execution-types** (002-types-and-traits): ExecutionEnvelope, ExecutionContext, sub-structs - Must - GENERATED
- [x] **003-decision-and-errors** (002-types-and-traits): Decision enum, DenyReason, TokenError, EvaluationError - Must - GENERATED
- [x] **004-trait-interfaces** (002-types-and-traits): PolicyEvaluator, TokenSigner, TokenVerifier, PolicyBundleStore, RevocationStore - Must - GENERATED

#### Unit: 002-paseto-v4

- [x] **001-paseto-signer** (003-paseto-v4): PasetoV4Signer implementing TokenSigner - Must - GENERATED
- [x] **002-paseto-verifier** (003-paseto-v4): PasetoV4Verifier implementing TokenVerifier - Must - GENERATED
- [x] **003-token-round-trip-tests** (003-paseto-v4): Comprehensive sign/verify/reject test suite - Must - GENERATED

### 003-grpc-protocol-wire-contract

*(No stories tracked — construction was completed directly)*

### 004-example-agents

#### Unit: 001-python-openai-agent

- [x] **001-agent-scaffold** (004-python-openai-agent): Agent definition, REPL, Makefile, .env.sample - Must - COMPLETE
- [x] **002-tool-definitions** (004-python-openai-agent): 9 tools across 5 categories (network, DB, file, email, shell) - Must - COMPLETE
- [x] **003-database-seed** (004-python-openai-agent): SQLite seed data and database service - Must - COMPLETE

#### Unit: 002-typescript-adk-agent

- [x] **001-agent-scaffold** (005-typescript-adk-agent): Agent definition, session loop, Makefile, .env.sample - Must - COMPLETE
- [x] **002-tool-definitions** (005-typescript-adk-agent): 9 tools with Zod schemas across 5 categories - Must - COMPLETE
- [x] **003-database-seed** (005-typescript-adk-agent): SQLite seed data and database service - Must - COMPLETE

---

## Stories by Status

- **Planned**: 0
- **Generated**: 11
- **In Progress**: 0
- **Completed**: 6
