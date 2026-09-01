# Changelog

User-facing changes are listed first. Internal improvements are grouped at the end.

## [Unreleased]

- `firma run` now waits for a human approval instead of exiting. When the
  Authority gates issuance on Human-In-The-Loop approval, the run prints the
  approval id, URL, and deadline on stderr, polls for the outcome, verifies
  the granted token locally, and starts the session; a denied or expired
  request stops the run with a clear error and no token. Two new profile
  settings tune the wait: `capability.approval_poll_interval` (default 5s)
  and `capability.approval_max_wait` (absent waits until the server-side
  deadline).

## [0.1.6](https://github.com/Firma-AI/openfirma/compare/v0.1.5...v0.1.6) - 2026-07-30

<details>
<summary>Internal Improvements</summary>

- Improve the release process ([#365](https://github.com/Firma-AI/openfirma/pull/365))

</details>
