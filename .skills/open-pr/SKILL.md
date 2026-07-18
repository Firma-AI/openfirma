---
name: open-pr
description: Open a GitHub pull request for OpenFirma. Use whenever you are asked to open a PR.
---

# Open PR

Use this workflow whenever you are asked to open a GitHub pull request for
OpenFirma.

## Workflow

1. Inspect the repository state and active VCS.
2. Inspect the revision stack that will be included in the PR.
3. Inspect bookmarks or branches and remotes.
4. If the working copy is dirty, the stack is mixed, or the target history is
   already under review, load and follow the
   [`commit-guidelines`](../commit-guidelines/SKILL.md) skill before
   continuing.
5. Read the [PR template](../../.github/pull_request_template.md).
6. Push the review head to the correct remote.
7. Open a **draft** PR with `gh`.
8. Concurrently, using sub-agents:
   1. Verify the final PR metadata and exact commit sequence with the read-only
      script documented below.
   2. Load and follow the [`verify`](../verify/SKILL.md) skill.
      If verification fails, provide the parent agent with a report so
      that it can address the issues.
   3. Perform an [adversarial PR review](../adversarial-review/SKILL.md).
9. Present the adversarial review findings to the user. Do not address or
   dismiss any finding until the user has reviewed it and provided explicit
   direction.
10. Iterate on the outcomes of the previous steps according to the user's
    direction until verification succeeds, the findings have been addressed or
    dismissed, and any resulting changes have been pushed and passed the
    verification and metadata checks in step 8. The updated PR must also pass
    another adversarial review unless the changes since the previous review are
    purely mechanical and do not change behavior or meaning.
11. Wait for the CI run triggered by the previous push with the read-only script
    documented below.
    It must succeed. If not, failures must be triaged and addressed.
12. Mark the PR as "ready to review".

For `jj` repositories, create or update a bookmark that points at the intended
review tip before pushing it to the selected remote.

## Verify after creation

After creating the PR, run:

```bash
uv run .skills/open-pr/scripts/verify_pr.py \
  --pr <url> \
  --expected-base <base> \
  --expected-head-owner <owner> \
  --expected-head-ref <ref> \
  --expected-head-sha <sha> \
  --expected-title <title> \
  --expected-draft true \
  --expected-commit <sha>
```

Repeat `--expected-commit` in PR order when the review head contains multiple
commits. The script verifies exact metadata, commit order, required template
sections, and empty placeholders. It does not judge whether the title and body
accurately explain the change; review those manually.

If the body does not match what you requested, fix it immediately instead of
assuming the create or edit step worked.

## Wait for CI

Wait for all checks on the expected head rather than starting an unjoined
background process:

```bash
uv run .skills/open-pr/scripts/wait_ci.py \
  --pr <url> \
  --expected-head-sha <sha> \
  --expected-check <required-check-name>
```

The script fails if a check other than `codecov/patch` fails, the PR head
changes, or the timeout expires. A failed `codecov/patch` returns
`manual_required` instead: inspect the coverage change and affected code, then
record why the signal is acceptable or requires additional tests before
continuing. Passing checks must remain unchanged for 30 seconds so that slower
workflows have time to register. Repeat `--expected-check` for every check
required by the repository; missing expected checks remain pending. Use
`--timeout`, `--poll-interval`, and `--settle-time` to override the defaults.

## Output

Report the PR URL.
