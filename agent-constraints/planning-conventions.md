# OpenFirma Planning Conventions

Ground every proposed change in the repository at the supplied immutable
revision. Inspect the implementation, tests, configuration, public contracts,
and documentation before proposing work.

Plans must:

- Preserve fail-closed behavior: errors and unclassifiable protected actions
  become `DENY` decisions.
- Preserve local, deterministic enforcement with no network access on the hot
  path and immutable execution envelopes after construction.
- Respect crate boundaries described in `AGENTS.md`; avoid introducing a
  dependency from `firma-core` to another workspace crate.
- Cover both supported platform families with `#[cfg(unix)]` and
  `#[cfg(windows)]` when behavior is platform-specific. Do not add fallback
  implementations for unsupported targets.
- Prefer the smallest cohesive change. Do not add compatibility behavior unless
  persisted data, shipped behavior, an external consumer, or the ticket requires
  it.
- Name concrete code, test, configuration, and documentation paths. Distinguish
  existing files from files that must be created.
- Include focused verification during implementation and `just check` as the
  final CI-parity gate. Follow the repository's Rust test guidelines when tests
  are added or moved.
- Include `docs-site/` and `docs-site/public/llms.txt` updates when the behavior,
  architecture, CLI, configuration, public API, discovery, or integration flow
  changes.

Use a decomposition only when independently reviewable child issues have clear,
non-overlapping ownership, explicit dependency order, and jointly satisfy the
parent ticket. Keep a cohesive change as one implementation plan.
