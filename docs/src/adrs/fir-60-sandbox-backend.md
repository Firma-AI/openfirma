<!-- ADR: FIR-60 | Status: Accepted (2026-04-24) -->

# FIR-60: Sandbox Backend Selection for firma-run

## Context

The sidecar's HTTP interception does not directly govern process-forking
execution — shell commands, browser automation, and sub-processes escape
enforcement unless network egress is structurally confined at the OS level.
On 2026-04-23, the architecture decision moved away from a second policy plane
and instead kept the sidecar as the single decision plane, relocating the hard
boundary to sandboxed process execution with mandatory egress routing through
the sidecar.

Decision drivers:

1. **Structural interception** — no reliance on cooperative `HTTP_PROXY`.
2. **Cross-platform coverage** — Linux, macOS, and Windows must each have a
   first-class path.
3. **Fast developer workflow** — interactive CLI usage must remain usable.
4. **Fail-closed posture** — no silent fallback when the sidecar path is
   unavailable.
5. **Reuse over reinvention** — no custom sandbox engine.
6. **Enterprise extensibility** — a stronger isolation profile must be possible
   without redesign.

## Decision

Adopted: **OS-specific multi-backend with common enforcement invariants.**

| Host OS            | Backend       | Isolation substrate            |
| ------------------ | ------------- | ------------------------------ |
| Linux              | `bwrap`       | Namespace/seccomp              |
| macOS              | `vz`          | Apple Virtualization Framework |
| Windows            | `wsl2`        | WSL2 Linux guest               |
| Linux (enterprise) | `firecracker` | KVM microVM (additive)         |

## Considered options

- **A — OS-specific multi-backend (selected)**: Preserves one enforcement model
  across all required OSes; allows a fast Linux path now and an enterprise
  microVM path later.
- **B — Firecracker-first**: Not selected — Linux/KVM-centric; no practical path
  for macOS or Windows defaults.
- **C — OCI runtime (Docker/Podman)**: Not selected — larger runtime and daemon
  surface than needed; does not improve the enforcement-plane model.
- **D — gVisor/Kata**: Not selected — better fit for orchestrated container
  fleets than local CLI wrapping; higher integration cost.
- **E — Linux-only release**: Rejected — fails the explicit cross-platform
  requirement.
- **F — Managed sandbox platforms**: Not selected — shifts trust and lifecycle
  ownership to an external control plane; licensing complexity.
- **G — Custom sandbox framework**: Rejected — high security and maintenance
  risk; reinvents mature OS primitives.

## Consequences

### Positive

- Structural egress confinement on Linux via `bwrap`; same enforcement model
  across all supported OSes.
- Single backend interface keeps future options (Firecracker, gVisor) additive
  without redesign.

### Negative / tradeoffs

- Larger test matrix and backend-specific operational code paths.
- macOS and Windows paths use proxy-mediated confinement, not structural
  namespace isolation.
- Firecracker remains Linux-only and non-default.

## References

- [firma-run Deep Dive](../architecture/firma-run.md)
- [Sidecar ↔ firma-run Relation](../architecture/sidecar-firma-run.md)
- [Bypass Analysis](../security/bypass-analysis.md)
