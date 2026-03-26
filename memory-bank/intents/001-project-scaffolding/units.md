---
intent: 001-project-scaffolding
phase: inception
status: units-defined
updated: 2026-03-26T10:15:00Z
---

# Unit Decomposition: 001-project-scaffolding

## Units

| Unit | Purpose | Stories | Bolt Type |
|------|---------|---------|-----------|
| 001-workspace-setup | Cargo workspace, all 4 crates, CI, Makefile | 4 | simple-construction-bolt |

## Requirement-to-Unit Mapping

- **FR-1**: Cargo Workspace Setup → `001-workspace-setup`
- **FR-2**: Crate Dependency Graph → `001-workspace-setup`
- **FR-3**: Stub Binary Entrypoints → `001-workspace-setup`
- **FR-4**: Clippy and Formatting → `001-workspace-setup`
- **FR-5**: CI Pipeline → `001-workspace-setup`
- **FR-6**: Makefile → `001-workspace-setup`
- **FR-7**: Proto Stub → `001-workspace-setup`

## Rationale

Single unit because all FRs are tightly coupled — you can't set up CI without having the workspace, and the Makefile mirrors CI. No domain logic to decompose.
