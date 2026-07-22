# Task 010 — Risk Context

| Field            | Value                                                      |
| ---------------- | ---------------------------------------------------------- |
| Status           | superseded in part by the `firma-protobuf` 0.2 migration   |
| Canonical plan   | `.claude/plans/2026-04-22-task-010-budget-risk-context.md` |
| Scope            | Tasks 1–8 in the Task 010 implementation plan              |
| Archive location | Left in `docs/tasks/` per working-tree handoff rules       |

## Acceptance Criteria

- [x] `build_context()` includes `risk_score`, `session_duration_s`, and
      `action_count`.
- [x] A Cedar policy referencing `risk_score > threshold` triggers DENY.
- [x] Unit coverage verifies the required context attributes are populated.

## Notes

- Budget tracking was removed when the wire contract moved to
  `firma-protobuf` 0.2. It will return only after its numeric model is
  redesigned without floating-point values.
- The common Cedar context fields used by both Authority and Sidecar are
  `session_id`, `timestamp_ms`, `params`, `risk_score`,
  `session_duration_s`, and `action_count`.
- `just check` is green modulo the known macOS timing flakes in
  `firma-authority::cedar_loader::tests::watch_reloads_on_policy_change`
  and `watch_subscribe_receives_bundle_update`.
