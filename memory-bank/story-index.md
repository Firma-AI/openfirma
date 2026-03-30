# Global Story Index

## Overview

- **Total stories**: 11
- **Generated**: 4
- **Planned**: 7
- **Last updated**: 2026-03-26

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

- [ ] **001-capability-token-types** (002-types-and-traits): CapabilityClaims struct, TokenState enum - Must - Planned
- [ ] **002-execution-types** (002-types-and-traits): ExecutionEnvelope, ExecutionContext, sub-structs - Must - Planned
- [ ] **003-decision-and-errors** (002-types-and-traits): Decision enum, DenyReason, TokenError, EvaluationError - Must - Planned
- [ ] **004-trait-interfaces** (002-types-and-traits): PolicyEvaluator, TokenSigner, TokenVerifier, PolicyBundleStore, RevocationStore - Must - Planned

#### Unit: 002-paseto-v4

- [ ] **001-paseto-signer** (003-paseto-v4): PasetoV4Signer implementing TokenSigner - Must - Planned
- [ ] **002-paseto-verifier** (003-paseto-v4): PasetoV4Verifier implementing TokenVerifier - Must - Planned
- [ ] **003-token-round-trip-tests** (003-paseto-v4): Comprehensive sign/verify/reject test suite - Must - Planned

---

## Stories by Status

- **Planned**: 7
- **Generated**: 4
- **In Progress**: 0
- **Completed**: 0
