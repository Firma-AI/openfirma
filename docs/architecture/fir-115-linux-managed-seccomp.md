# Linux Managed Seccomp Pipeline

Status: implementation baseline  
Date: 2026-05-11  
Scope: Linux `firma run` + `bwrap` local-command enforcement
Card reference: FIR-115

## Summary

This implementation provides a production-oriented Linux path that keeps static seccomp as
the authoritative fail-closed layer, while adding a managed policy pipeline:

1. Cedar-subset intent (action classes) is declared in a source policy file.
2. `firma-run` compiles that policy into a deterministic static seccomp cBPF artifact.
3. The artifact is versioned on disk and paired with JSON metadata + checksum.
4. Runtime verifies checksum before loading the filter into `bwrap --seccomp`.

Legacy `seccomp_bpf_path` remains supported for migration compatibility.

## Supported Cedar Subset (deny actions)

Current supported actions:

1. `system.execute`
2. `filesystem.delete`
3. `credential.write`

Unsupported actions are rejected explicitly during compilation.

## Runtime model

1. Static seccomp remains process-static by design (no in-place hot reload).
2. Policy updates are applied by generating a new versioned artifact and launching
   a new sandbox/run.
3. Checksum mismatch, invalid metadata, or unreadable artifacts fail closed.

## Policy file example

Baseline source policy shipped in-repo:

`crates/firma-run/policies/generic-local-command-v1.toml`

```toml
policy_id = "generic-local-command"
policy_version = "v1"
default_action = "allow"
deny_actions = ["system.execute", "filesystem.delete", "credential.write"]
```

For the `generic` baseline we intentionally do **not** deny `system.execute`,
because denying `execve/execveat` at this layer breaks normal command startup.
That action remains supported for narrower/specialized profiles where such
behavior is explicitly intended.

## `firma-run` config example

```toml
[profiles.generic]
backend = "bwrap"

[profiles.generic.seccomp_managed]
source_policy_path = "/abs/path/to/crates/firma-run/policies/generic-local-command-v1.toml"
artifact_dir = "/abs/path/to/.firma/seccomp-artifacts"
verify_checksum = true
```

Notes:

1. `seccomp_managed` is Linux + `bwrap` only.
2. `seccomp_managed` and legacy `seccomp_bpf_path` are mutually exclusive.

## Compatibility constraints

Managed static seccomp support is currently constrained to:

1. Linux host
2. `bwrap` backend
3. CPU arch: `x86_64` or `aarch64`
4. Kernel: `>= 4.14`
5. Seccomp actions available: `kill_process`, `errno`, `allow`

Validated via:

1. `scripts/seccomp/check-managed-compatibility.sh`
2. `make managed-seccomp-compat-check`

CI guardrail stores compatibility output in:

1. `.spike-output/managed-seccomp-guardrail-*/compatibility.txt`

## Artifact contract

Generated metadata includes:

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

Quick integrity inspection command:

1. `scripts/seccomp/inspect-managed-artifact.sh --artifact /abs/path/policy.bpf --metadata /abs/path/policy.metadata.json`

## Validation matrix (recommended)

Unit-level:

1. `cargo test -p firma-run seccomp::tests`
2. `cargo test -p firma-run config::tests::seccomp_managed_resolves_when_configured_for_bwrap`
3. `cargo test -p firma-run config::tests::seccomp_managed_rejected_for_non_bwrap_backend`
4. `cargo test -p firma-run config::tests::seccomp_managed_and_legacy_path_are_mutually_exclusive`

Guardrail/CI-level (Linux):

1. `make managed-seccomp-compat-check`
2. `make managed-seccomp-guardrail`
3. Guardrail enforcement coverage:
4. release-mode baseline vs managed overhead threshold
5. artifact + metadata generation
6. compatibility check output artifact
7. fail-closed check for missing managed source policy
8. focused seccomp unit suite
