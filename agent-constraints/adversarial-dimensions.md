# OpenFirma Adversarial Review Dimensions

Independently verify the candidate against the repository at the supplied
revision. Report only concrete, actionable findings tied to plan sections or
repository paths.

Check for:

- Incorrect assumptions about current behavior, crate ownership, public
  contracts, configuration loading, or generated protobuf code.
- Any path that weakens fail-closed enforcement, adds network access to the hot
  path, makes enforcement nondeterministic, or mutates an execution envelope.
- Missing Unix or Windows behavior, or accidental fallback support for
  unsupported targets.
- Security boundary failures involving capability validation, policy
  enforcement, revocation, credentials, untrusted inputs, or sidecar/Authority
  separation.
- Partial-failure and recovery gaps, including retries that can duplicate remote
  effects or overwrite human-owned state.
- Incomplete tests, incorrect verification commands, strict lint violations, or
  missing documentation and `llms.txt` updates.
- Unnecessary compatibility layers, speculative abstractions, unrelated cleanup,
  or scope that is too broad to review safely.
- Decompositions whose children overlap, omit integration work, depend on
  undefined outputs, or form a dependency cycle.

Approve only when repository inspection supports the design and no actionable
finding remains.
