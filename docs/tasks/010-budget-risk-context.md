# Task 010 — Budget and Risk Context

| Field            | Value                                                      |
| ---------------- | ---------------------------------------------------------- |
| Status           | done                                                       |
| Canonical plan   | `.claude/plans/2026-04-22-task-010-budget-risk-context.md` |
| Scope            | Tasks 1–8 in the Task 010 implementation plan              |
| Archive location | Left in `docs/tasks/` per working-tree handoff rules       |

## Acceptance Criteria

- [x] `build_context()` includes `budget_remaining`, `risk_score`,
      `session_duration_s`, and `action_count`.
- [x] A Cedar policy referencing `budget_remaining < 0` triggers DENY.
- [x] A Cedar policy referencing `risk_score > threshold` triggers DENY.
- [x] Unit coverage verifies the required context attributes are populated.

## Notes

- The reconciled canonical Cedar context shape is the 7-field schema now
  used by both Authority and Sidecar: `session_id`, `timestamp_ms`,
  `params`, `risk_score`, `budget_remaining`, `session_duration_s`, and
  `action_count`.
- `just check` is green modulo the known macOS timing flakes in
  `firma-authority::cedar_loader::tests::watch_reloads_on_policy_change`
  and `watch_subscribe_receives_bundle_update`.
