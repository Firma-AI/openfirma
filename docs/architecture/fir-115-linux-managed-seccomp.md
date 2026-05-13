# Linux Managed Seccomp Pipeline (FIR-115)

Status: implementation complete (Linux path)  
Date: 2026-05-13  
Scope: `firma run` + Linux `bwrap` backend

## Full Validation Runbook

1. End-to-end verification steps are documented in:
`docs/architecture/fir-115-validation-runbook.md`

## Decision

1. Linux syscall deny enforcement remains static seccomp cBPF in kernel space.
2. Cedar is compiled from an approved subset into versioned static seccomp artifacts.
3. Runtime resolves and verifies artifacts before launch; verification failures fail closed.
4. No in-place hot reload for active sandboxes; policy updates apply on next launch.

## Cedar subset (supported deny actions)

1. `system.execute`
2. `filesystem.delete`
3. `credential.write`

Unsupported actions are rejected at compile/load time with explicit errors.

Current mapping:

1. `system.execute` -> `execve`, `execveat`
2. `filesystem.delete` -> `unlink`, `unlinkat`, `rmdir`, `rename`, `renameat`, `renameat2`
3. `credential.write` -> `setuid`, `setgid`, `setresuid`, `setresgid`

## Cedar fidelity caveats (concrete)

Static seccomp is syscall-number enforcement, so fidelity to Cedar intent is intentionally bounded.

1. No argument-level policy expression at kernel layer:
`filesystem.delete` can deny delete/rename syscalls, but it cannot encode path-based intent (for example, "allow delete in workspace, deny delete in /etc") inside the seccomp filter itself.
2. Rename semantics are broader than "delete intent":
`rename*` is included for conservative safety because it can replace targets atomically; this can also block benign atomic-update patterns.
3. Architecture-dependent syscall surfaces:
on `aarch64`, legacy `unlink`/`rmdir` syscall numbers are absent and equivalent behavior routes through `unlinkat`/`renameat*`; effective deny lists therefore differ by target arch.
4. No dynamic runtime context in kernel decision:
HITL, budget/rate state, tenant context, and session freshness are out of scope for static seccomp and must remain in userspace policy layers.

## Unsupported mappings and rationale

Current compiler rejects unsupported Cedar actions because mapping them to static syscall policy would be unsound or overbroad.

1. `system.install` (and unknown actions) are rejected:
there is no narrow syscall-only projection that preserves policy intent without high false-positive or false-negative risk.
2. Non-`allow` default actions are rejected:
the static baseline uses `allow` default plus explicit deny syscall set for deterministic behavior and compatibility with current rollout profile.

## Authoritative runtime path

1. Runtime resolves the effective managed seccomp artifact.
2. Runtime passes artifact path via launch contract (`LaunchSpec`) to Linux backend.
3. Linux backend opens descriptor and passes `--seccomp <fd>` to `bwrap`.
4. If `command_mediator` is configured, runtime performs a mandatory pre-exec mediator decision check before launching the wrapped command.

Important hardening:

1. Environment-variable seccomp injection fallback is removed.
2. `seccomp_policy.verify_checksum=false` is rejected.
3. Artifact checksum verification is mandatory in both compile-on-launch and precompiled-only modes.
4. Artifact root/leaf directories and artifact files must be owned by the current runtime uid.
5. Other-write permissions on managed artifact paths are rejected.
6. Symlinked managed artifact paths are rejected.
7. In mediated mode, timeout/unavailable/error from mediator fails closed (no direct exec fallback).

## Userspace mediator layer (implemented)

This layer complements static seccomp; it is not a syscall containment boundary.

1. Decision point:
`firma run` resolves final executable + args, then sends a decision request to mediator before process launch.
2. Identity/session binding:
request includes `sandbox_id`, `session_id`, and `profile` to prevent cross-session confusion.
3. Decision model:
1. `allow` -> launch proceeds
2. `deny` -> launch blocked
3. `pending_hitl` -> launch blocked (explicit fail-closed pending state)
4. timeout/unavailable/invalid response -> launch blocked
4. Endpoint forms:
1. `tcp://host:port`
2. `unix:///absolute/path.sock`
5. Request contract (JSON line):
`{"action":"local.exec","executable":"...","args":[...],"sandbox_id":"...","session_id":"...","profile":"..."}`
6. Response contract (JSON line):
`{"decision":"allow|deny|pending_hitl","reason":"optional"}`.
Any unsupported/malformed response is fail-closed.

## Artifact contract

Metadata fields:

1. `policy_schema_version`
2. `policy_id`
3. `policy_version`
4. `sha256`
5. `generated_at`
6. `compiler_version`
7. `target_arch`
8. `default_action`
9. `source_policy_refs`
10. `source_policy_sha256`
11. `denied_syscalls`

Layout:

1. `<artifact_dir>/<policy_id>/<policy_version>/<target_arch>/policy.bpf`
2. `<artifact_dir>/<policy_id>/<policy_version>/<target_arch>/policy.metadata.json`

## Default Linux profile behavior

For `generic` on Linux + `bwrap`, managed seccomp is default-enabled with:

1. Source policy: bundled `crates/firma-run/policies/generic-local-command-v1.toml`
2. Artifact dir default: `/tmp/firma/seccomp-artifacts`
3. Runtime mode default: `compile_on_launch`
4. Checksum verification: mandatory

Optional runtime overrides:

1. `FIRMA_RUN_MANAGED_SECCOMP_POLICY_PATH` (absolute policy path)
2. `FIRMA_RUN_MANAGED_SECCOMP_ARTIFACT_DIR` (absolute artifact root)
3. `FIRMA_RUN_MANAGED_SECCOMP_RUNTIME_MODE` (`compile_on_launch` or `precompiled_only`)
4. `FIRMA_RUN_MANAGED_SECCOMP_DISABLE_DEFAULT` (truthy disables built-in generic default for rollback/testing)

## Explicit policy update model

1. Seccomp filter is static per sandbox process.
2. Policy update means: new artifact version + new launch.
3. Existing sandbox instances keep prior filter until exit.
4. Unresolvable/unverifiable artifact blocks launch (fail closed).
5. Unloadable or invalid-but-checksummed artifact content blocks launch (fail closed).

## Migration from legacy/manual path

Current supported migration:

1. Remove manual seccomp wiring and rely on managed `seccomp_policy` artifacts.
2. Prefer profile-managed policy with versioned artifacts.
3. For controlled rollouts, use `runtime_mode = "precompiled_only"` with known-good artifact versions.

Notes:

1. Environment-based seccomp path injection is no longer authoritative.
2. Rollback is profile-level artifact version switch or temporary default-disable flag.

## Compatibility matrix

Managed static seccomp is supported for:

1. OS: Linux
2. Backend: `bwrap`
3. Arch: `x86_64`, `aarch64`
4. Kernel: `>= 4.14`
5. Required seccomp actions: `kill_process`, `errno`, `allow`

Validation tooling:

1. `make managed-seccomp-compat-check`
2. `scripts/seccomp/check-managed-compatibility.sh`

## CI/local guardrails

Primary guardrail:

1. `make managed-seccomp-guardrail`

Checks enforced:

1. Release-mode overhead gate (`<= 3%` avg latency overhead on FIR-111 shell-heavy workload)
2. Artifact and metadata generation
3. Artifact checksum/metadata integrity inspection
4. Fail-closed behavior for:
5. missing policy source
6. missing precompiled artifact
7. invalid artifact metadata format
8. checksum mismatch
9. unloadable artifact
10. invalid readable BPF artifact (checksum-valid but rejected by runtime load path)

## Runbook

### Publish/update policy

1. Edit Cedar-subset policy source (`policy_id`, `policy_version`, actions).
2. Run `make managed-seccomp-compat-check`.
3. Run `make managed-seccomp-guardrail`.
4. Promote artifacts by version and update profile refs if using precompiled-only.

### Incident/rollback

1. Switch profile to previous known-good artifact version (precompiled-only mode), or
2. set `FIRMA_RUN_MANAGED_SECCOMP_DISABLE_DEFAULT=1` for emergency temporary disable in generic Linux profile.
3. Re-run compatibility + guardrail checks before re-enable.
4. Ensure promoted artifact directories/files remain uid-owned and not other-writable.

### Verification commands

1. `cargo test -p firma-run seccomp::tests`
2. `cargo test -p firma-run seccomp_policy_`
3. `scripts/seccomp/inspect-managed-artifact.sh --artifact /abs/path/policy.bpf --metadata /abs/path/policy.metadata.json`
