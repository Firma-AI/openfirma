<!--
Keep this PR description skimmable:
- Title: `type(scope)!: description`
- Types: ai, build, chore, ci, docs, feat, fix, perf, refactor, revert,
  security, style, test
- 1-3 sentences in "Why"
- 3-5 bullets in "What Changed"
- Prefer links to issues/docs over repeated background
- Keep "Design Plan"; delete any other section that does not apply
-->

## Why

<!--
1-3 sentences. What problem does this solve, and why is it worth doing now?
Link the issue, decision doc, or discussion instead of repeating background.
-->

## What Changed

<!-- 3-5 short bullets. Focus on meaningful changes, not implementation play-by-play. -->

-

## Design Plan

<!--
Required. Keep this section for every PR.

For Full or Compact planning, link the accepted plan at an immutable blob URL
containing the full first-commit SHA and stable plan path, and record its
immutable ownership base. Do not link a path at HEAD. The closing removal commit
stays pending until implementation review and all finding dispositions are
complete; update it before marking the PR ready.

For a no-plan exemption, write "Not applicable" and give the routing reason.
Do not create a plan artifact merely to fill this section.
-->

- Planning: Full | Compact | Not applicable — <exemption reason>
- PR ownership base: Not applicable | `<full parent SHA of first plan commit>`
- Accepted plan: Not applicable | [<full SHA>:<path>](https://github.com/Firma-AI/openfirma/blob/<full-SHA>/<path>)
- Current reviewed plan: Not applicable | Same as accepted | [<full SHA>:<same path>](https://github.com/Firma-AI/openfirma/blob/<full-SHA>/<same-path>)
- Post-implementation review: Pending | Complete — <reviewed full tip SHA and finding disposition evidence>
- Closing plan removal: Pending | Not applicable | `<full deletion-only commit SHA>`
- Lifecycle verification: Pending | Not applicable | Complete

## Manual / Extra Verification

<!--
Delete this section unless you did validation beyond the repo's standard
automated checks.

Do not list `just ...`, `cargo test`, linters, formatters, or CI jobs here.
Use this section only for manual testing, environment-specific validation, or
coverage gaps that automated checks could not exercise.

Include exact steps, screenshots, logs, or environment details when relevant.
-->

## Risks / Notes

<!--
Only include things a reviewer might miss or should double-check before merge.

Delete this section if there is nothing notable.

Examples:
- tricky logic or tradeoffs where reviewer attention is most useful
- important invariants or assumptions to double-check
- hot-path or fail-closed behavior changes
- trust-boundary or security-sensitive changes
- config, wire-format, or migration impact
- follow-up work or known limitations
-->

## AI Assistance

<!-- Optional concise disclosure. Delete this section if not used. If you want to share, include the model name/ID. -->
