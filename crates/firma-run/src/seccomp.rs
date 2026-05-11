use std::collections::BTreeSet;
use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::{ManagedSeccompPolicyConfig, ResolvedProfile};
use crate::error::RunError;

const FILTER_CODE_LD_W_ABS: u16 = 0x20;
const FILTER_CODE_JMP_JEQ_K: u16 = 0x15;
const FILTER_CODE_RET_K: u16 = 0x06;

const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
const COMPILER_VERSION: &str = "managed-seccomp-v1";
const POLICY_SCHEMA_VERSION: u32 = 1;
const EPERM_ERRNO: u32 = 1;

/// Runtime seccomp materialization outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeccompMaterialized {
    pub bpf_path: PathBuf,
}

/// Resolve the effective seccomp filter for a profile.
///
/// Legacy `seccomp_bpf_path` is preserved as-is. Managed policy mode compiles
/// a deterministic artifact and returns the generated filter path.
///
/// # Errors
///
/// Returns an error when managed policy compilation, artifact write, or
/// checksum verification fails.
pub fn resolve_effective_seccomp(
    profile: &ResolvedProfile,
) -> Result<Option<SeccompMaterialized>, RunError> {
    if let Some(path) = &profile.seccomp_bpf_path {
        return Ok(Some(SeccompMaterialized {
            bpf_path: path.clone(),
        }));
    }

    let Some(managed) = &profile.seccomp_managed else {
        return Ok(None);
    };

    let generated = compile_managed_seccomp(managed)?;
    Ok(Some(generated))
}

#[derive(Debug, Clone, Deserialize)]
struct CedarSubsetPolicyFile {
    policy_id: String,
    policy_version: String,
    #[serde(default = "default_policy_action")]
    default_action: String,
    #[serde(default)]
    deny_actions: Vec<String>,
    #[serde(default)]
    source_policy_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManagedSeccompArtifactMetadata {
    pub policy_schema_version: u32,
    pub policy_id: String,
    pub policy_version: String,
    pub sha256: String,
    pub generated_at: String,
    pub compiler_version: String,
    pub target_arch: String,
    pub default_action: String,
    pub source_policy_refs: Vec<String>,
    pub source_policy_sha256: String,
    pub denied_syscalls: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetArch {
    X86_64,
    Aarch64,
}

impl TargetArch {
    fn as_str(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
        }
    }

    fn audit_arch_value(self) -> u32 {
        // Values from linux/audit.h:
        // AUDIT_ARCH_X86_64 = EM_X86_64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE = 0xC000003E
        // AUDIT_ARCH_AARCH64 = EM_AARCH64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE = 0xC00000B7
        match self {
            Self::X86_64 => 0xC000_003E,
            Self::Aarch64 => 0xC000_00B7,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SyscallId {
    Execve,
    Execveat,
    Rename,
    Renameat,
    Renameat2,
    Rmdir,
    Setgid,
    Setresgid,
    Setresuid,
    Setuid,
    Unlink,
    Unlinkat,
}

impl SyscallId {
    fn name(self) -> &'static str {
        match self {
            Self::Execve => "execve",
            Self::Execveat => "execveat",
            Self::Rename => "rename",
            Self::Renameat => "renameat",
            Self::Renameat2 => "renameat2",
            Self::Rmdir => "rmdir",
            Self::Setgid => "setgid",
            Self::Setresgid => "setresgid",
            Self::Setresuid => "setresuid",
            Self::Setuid => "setuid",
            Self::Unlink => "unlink",
            Self::Unlinkat => "unlinkat",
        }
    }

    fn number_for_arch(self, target_arch: TargetArch) -> Option<u32> {
        match target_arch {
            TargetArch::X86_64 => match self {
                Self::Execve => Some(59),
                Self::Execveat => Some(322),
                Self::Rename => Some(82),
                Self::Renameat => Some(264),
                Self::Renameat2 => Some(316),
                Self::Rmdir => Some(84),
                Self::Setgid => Some(106),
                Self::Setresgid => Some(119),
                Self::Setresuid => Some(117),
                Self::Setuid => Some(105),
                Self::Unlink => Some(87),
                Self::Unlinkat => Some(263),
            },
            TargetArch::Aarch64 => match self {
                Self::Execve => Some(221),
                Self::Execveat => Some(281),
                Self::Rename | Self::Rmdir | Self::Unlink => None,
                Self::Renameat => Some(38),
                Self::Renameat2 => Some(276),
                Self::Setgid => Some(144),
                Self::Setresgid => Some(149),
                Self::Setresuid => Some(147),
                Self::Setuid => Some(146),
                Self::Unlinkat => Some(35),
            },
        }
    }
}

fn default_policy_action() -> String {
    "allow".to_string()
}

fn compile_managed_seccomp(
    managed: &ManagedSeccompPolicyConfig,
) -> Result<SeccompMaterialized, RunError> {
    if !cfg!(target_os = "linux") {
        return Err(RunError::ConfigValidation(
            "managed seccomp policy is supported only on Linux hosts".to_string(),
        ));
    }

    let policy_src = fs::read_to_string(&managed.source_policy_path).map_err(|error| {
        RunError::ConfigValidation(format!(
            "failed to read managed seccomp policy {}: {error}",
            managed.source_policy_path.display()
        ))
    })?;
    let source_policy_sha = sha256_hex(policy_src.as_bytes());

    let parsed: CedarSubsetPolicyFile = toml::from_str(&policy_src).map_err(|error| {
        RunError::ConfigValidation(format!(
            "invalid managed seccomp policy {}: {error}",
            managed.source_policy_path.display()
        ))
    })?;
    if parsed.policy_id.trim().is_empty() {
        return Err(RunError::ConfigValidation(
            "managed seccomp policy_id must not be empty".to_string(),
        ));
    }
    if parsed.policy_version.trim().is_empty() {
        return Err(RunError::ConfigValidation(
            "managed seccomp policy_version must not be empty".to_string(),
        ));
    }
    if parsed.default_action != "allow" {
        return Err(RunError::ConfigValidation(format!(
            "managed seccomp default_action '{}' is unsupported; only 'allow' is currently supported",
            parsed.default_action
        )));
    }

    let target_arch = current_target_arch()?;
    let (syscalls, unsupported_actions) = map_actions_to_syscalls(&parsed.deny_actions);
    if !unsupported_actions.is_empty() {
        return Err(RunError::ConfigValidation(format!(
            "managed seccomp policy contains unsupported Cedar actions: {}; supported deny actions are: system.execute, filesystem.delete, credential.write",
            unsupported_actions.join(", ")
        )));
    }

    let (bpf_bytes, effective_syscalls) = emit_bpf_program(target_arch, &syscalls);
    let bpf_sha = sha256_hex(&bpf_bytes);

    let rel_dir = format!(
        "{}/{}/{}",
        sanitize_path_segment(&parsed.policy_id),
        sanitize_path_segment(&parsed.policy_version),
        target_arch.as_str()
    );
    let output_dir = managed.artifact_dir.join(rel_dir);
    fs::create_dir_all(&output_dir).map_err(|error| {
        RunError::ConfigValidation(format!(
            "failed to create managed seccomp artifact dir {}: {error}",
            output_dir.display()
        ))
    })?;
    let bpf_path = output_dir.join("policy.bpf");
    let metadata_path = output_dir.join("policy.metadata.json");

    write_atomic(&bpf_path, &bpf_bytes)?;

    let metadata = ManagedSeccompArtifactMetadata {
        policy_schema_version: POLICY_SCHEMA_VERSION,
        policy_id: parsed.policy_id,
        policy_version: parsed.policy_version,
        sha256: bpf_sha,
        generated_at: Utc::now().to_rfc3339(),
        compiler_version: COMPILER_VERSION.to_string(),
        target_arch: target_arch.as_str().to_string(),
        default_action: parsed.default_action,
        source_policy_refs: if parsed.source_policy_refs.is_empty() {
            vec![managed.source_policy_path.display().to_string()]
        } else {
            parsed.source_policy_refs
        },
        source_policy_sha256: source_policy_sha,
        denied_syscalls: effective_syscalls,
    };
    let metadata_bytes = serde_json::to_vec_pretty(&metadata).map_err(|error| {
        RunError::Internal(format!(
            "failed to serialize managed seccomp metadata: {error}"
        ))
    })?;
    write_atomic(&metadata_path, &metadata_bytes)?;

    if managed.verify_checksum {
        verify_artifact_checksum(&bpf_path, &metadata_path)?;
    }

    Ok(SeccompMaterialized { bpf_path })
}

fn verify_artifact_checksum(bpf_path: &Path, metadata_path: &Path) -> Result<(), RunError> {
    let metadata_bytes = fs::read(metadata_path).map_err(|error| {
        RunError::ConfigValidation(format!(
            "failed to read managed seccomp metadata {}: {error}",
            metadata_path.display()
        ))
    })?;
    let metadata: ManagedSeccompArtifactMetadata = serde_json::from_slice(&metadata_bytes)
        .map_err(|error| {
            RunError::ConfigValidation(format!(
                "failed to parse managed seccomp metadata {}: {error}",
                metadata_path.display()
            ))
        })?;

    let file_bytes = fs::read(bpf_path).map_err(|error| {
        RunError::ConfigValidation(format!(
            "failed to read managed seccomp artifact {}: {error}",
            bpf_path.display()
        ))
    })?;
    let actual_sha = sha256_hex(&file_bytes);
    if actual_sha != metadata.sha256 {
        return Err(RunError::ConfigValidation(format!(
            "managed seccomp checksum mismatch for {}: expected {}, got {}",
            bpf_path.display(),
            metadata.sha256,
            actual_sha
        )));
    }
    Ok(())
}

fn sanitize_path_segment(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        let allowed = ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.');
        out.push(if allowed { ch } else { '_' });
    }
    let trimmed = out.trim_matches('.');
    if out.is_empty() || trimmed.is_empty() || out == "." || out == ".." {
        "_".to_string()
    } else {
        out
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), RunError> {
    let ext = path
        .extension()
        .and_then(std::ffi::OsStr::to_str)
        .filter(|s| !s.is_empty())
        .unwrap_or("tmp");
    let pid = std::process::id();
    let now_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    let mut last_err: Option<std::io::Error> = None;
    for attempt in 0_u32..32_u32 {
        let tmp = path.with_extension(format!("{ext}.tmp.{pid}.{now_nanos}.{attempt}"));
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp);
        let mut file = match file {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                last_err = Some(error);
                continue;
            }
            Err(error) => {
                return Err(RunError::ConfigValidation(format!(
                    "failed to create temporary file {}: {error}",
                    tmp.display()
                )));
            }
        };

        if let Err(error) = file.write_all(bytes) {
            let _ = fs::remove_file(&tmp);
            return Err(RunError::ConfigValidation(format!(
                "failed to write temporary file {}: {error}",
                tmp.display()
            )));
        }
        if let Err(error) = file.sync_all() {
            let _ = fs::remove_file(&tmp);
            return Err(RunError::ConfigValidation(format!(
                "failed to sync temporary file {}: {error}",
                tmp.display()
            )));
        }
        drop(file);

        if let Err(error) = fs::rename(&tmp, path) {
            let _ = fs::remove_file(&tmp);
            return Err(RunError::ConfigValidation(format!(
                "failed to finalize file {}: {error}",
                path.display()
            )));
        }
        return Ok(());
    }

    Err(RunError::ConfigValidation(format!(
        "failed to create unique temporary file for {} after multiple attempts: {}",
        path.display(),
        last_err.map_or_else(|| "unknown error".to_string(), |e| e.to_string())
    )))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    hex::encode(digest)
}

fn current_target_arch() -> Result<TargetArch, RunError> {
    if cfg!(target_arch = "x86_64") {
        return Ok(TargetArch::X86_64);
    }
    if cfg!(target_arch = "aarch64") {
        return Ok(TargetArch::Aarch64);
    }
    Err(RunError::ConfigValidation(
        "managed seccomp supports only x86_64 and aarch64 targets".to_string(),
    ))
}

fn map_actions_to_syscalls(actions: &[String]) -> (Vec<SyscallId>, Vec<String>) {
    let mut syscalls = BTreeSet::new();
    let mut unsupported = Vec::new();

    for action in actions {
        match action.as_str() {
            "system.execute" => {
                syscalls.insert(SyscallId::Execve);
                syscalls.insert(SyscallId::Execveat);
            }
            "filesystem.delete" => {
                syscalls.insert(SyscallId::Unlink);
                syscalls.insert(SyscallId::Unlinkat);
                syscalls.insert(SyscallId::Rmdir);
                syscalls.insert(SyscallId::Rename);
                syscalls.insert(SyscallId::Renameat);
                syscalls.insert(SyscallId::Renameat2);
            }
            "credential.write" => {
                syscalls.insert(SyscallId::Setuid);
                syscalls.insert(SyscallId::Setgid);
                syscalls.insert(SyscallId::Setresuid);
                syscalls.insert(SyscallId::Setresgid);
            }
            // Explicitly rejected in the managed baseline policy profile.
            "system.install" => unsupported.push(action.clone()),
            other => unsupported.push(other.to_string()),
        }
    }

    (syscalls.into_iter().collect(), unsupported)
}

fn emit_bpf_program(
    target_arch: TargetArch,
    denied_syscalls: &[SyscallId],
) -> (Vec<u8>, Vec<String>) {
    let mut out = Vec::new();
    let mut effective_syscalls = Vec::new();

    // Verify seccomp_data.arch first.
    emit_stmt(&mut out, FILTER_CODE_LD_W_ABS, SECCOMP_DATA_ARCH_OFFSET);
    emit_jump(
        &mut out,
        FILTER_CODE_JMP_JEQ_K,
        target_arch.audit_arch_value(),
        1,
        0,
    );
    emit_stmt(&mut out, FILTER_CODE_RET_K, SECCOMP_RET_KILL_PROCESS);

    // Load syscall number.
    emit_stmt(&mut out, FILTER_CODE_LD_W_ABS, SECCOMP_DATA_NR_OFFSET);

    for syscall in denied_syscalls {
        let Some(nr) = syscall.number_for_arch(target_arch) else {
            continue;
        };
        emit_jump(&mut out, FILTER_CODE_JMP_JEQ_K, nr, 0, 1);
        emit_stmt(&mut out, FILTER_CODE_RET_K, SECCOMP_RET_ERRNO | EPERM_ERRNO);
        effective_syscalls.push(syscall.name().to_string());
    }

    emit_stmt(&mut out, FILTER_CODE_RET_K, SECCOMP_RET_ALLOW);
    (out, effective_syscalls)
}

fn emit_stmt(out: &mut Vec<u8>, code: u16, k: u32) {
    out.extend_from_slice(&code.to_ne_bytes());
    out.push(0);
    out.push(0);
    out.extend_from_slice(&k.to_ne_bytes());
}

fn emit_jump(out: &mut Vec<u8>, code: u16, k: u32, jt: u8, jf: u8) {
    out.extend_from_slice(&code.to_ne_bytes());
    out.push(jt);
    out.push(jf);
    out.extend_from_slice(&k.to_ne_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_supported_actions_to_expected_syscalls() {
        let actions = vec![
            "system.execute".to_string(),
            "filesystem.delete".to_string(),
            "credential.write".to_string(),
        ];
        let (syscalls, unsupported) = map_actions_to_syscalls(&actions);
        assert!(unsupported.is_empty());
        assert!(syscalls.contains(&SyscallId::Execve));
        assert!(syscalls.contains(&SyscallId::Unlinkat));
        assert!(syscalls.contains(&SyscallId::Setresuid));
    }

    #[test]
    fn reports_unsupported_actions() {
        let actions = vec!["system.install".to_string(), "foo.bar".to_string()];
        let (_syscalls, unsupported) = map_actions_to_syscalls(&actions);
        assert_eq!(unsupported, actions);
    }

    #[test]
    fn compiles_artifact_and_verifies_checksum() {
        let tempdir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let policy_path = tempdir.path().join("policy.toml");
        fs::write(
            &policy_path,
            r#"
policy_id = "generic-local-command"
policy_version = "v1"
default_action = "allow"
deny_actions = ["filesystem.delete", "system.execute"]
"#,
        )
        .unwrap_or_else(|e| panic!("{e}"));

        let artifacts = tempdir.path().join("artifacts");
        let managed = ManagedSeccompPolicyConfig {
            source_policy_path: policy_path,
            artifact_dir: artifacts,
            verify_checksum: true,
        };

        let out = compile_managed_seccomp(&managed).unwrap_or_else(|e| panic!("{e}"));
        assert!(out.bpf_path.is_file());
        let metadata_path = out
            .bpf_path
            .parent()
            .unwrap_or_else(|| panic!("missing parent"))
            .join("policy.metadata.json");
        assert!(metadata_path.is_file());
    }

    #[test]
    fn checksum_verification_fails_on_tampered_artifact() {
        let tempdir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let policy_path = tempdir.path().join("policy.toml");
        fs::write(
            &policy_path,
            r#"
policy_id = "generic-local-command"
policy_version = "v1"
default_action = "allow"
deny_actions = ["filesystem.delete"]
"#,
        )
        .unwrap_or_else(|e| panic!("{e}"));

        let artifacts = tempdir.path().join("artifacts");
        let managed = ManagedSeccompPolicyConfig {
            source_policy_path: policy_path,
            artifact_dir: artifacts,
            verify_checksum: true,
        };

        let out = compile_managed_seccomp(&managed).unwrap_or_else(|e| panic!("{e}"));
        let metadata_path = out
            .bpf_path
            .parent()
            .unwrap_or_else(|| panic!("missing parent"))
            .join("policy.metadata.json");
        fs::write(&out.bpf_path, [1_u8, 2, 3, 4]).unwrap_or_else(|e| panic!("{e}"));

        let err = verify_artifact_checksum(&out.bpf_path, &metadata_path)
            .expect_err("expected checksum mismatch");
        assert!(
            err.to_string()
                .contains("managed seccomp checksum mismatch"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn fails_when_policy_source_missing() {
        let tempdir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let managed = ManagedSeccompPolicyConfig {
            source_policy_path: tempdir.path().join("missing.toml"),
            artifact_dir: tempdir.path().join("artifacts"),
            verify_checksum: true,
        };
        let err = compile_managed_seccomp(&managed).expect_err("expected missing policy failure");
        assert!(
            err.to_string()
                .contains("failed to read managed seccomp policy"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn fails_on_unsupported_action() {
        let tempdir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let policy_path = tempdir.path().join("policy.toml");
        fs::write(
            &policy_path,
            r#"
policy_id = "generic-local-command"
policy_version = "v1"
default_action = "allow"
deny_actions = ["system.install"]
"#,
        )
        .unwrap_or_else(|e| panic!("{e}"));
        let managed = ManagedSeccompPolicyConfig {
            source_policy_path: policy_path,
            artifact_dir: tempdir.path().join("artifacts"),
            verify_checksum: true,
        };
        let err = compile_managed_seccomp(&managed).expect_err("expected unsupported action error");
        assert!(
            err.to_string()
                .contains("managed seccomp policy contains unsupported Cedar actions"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn fails_on_unsupported_default_action() {
        let tempdir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let policy_path = tempdir.path().join("policy.toml");
        fs::write(
            &policy_path,
            r#"
policy_id = "generic-local-command"
policy_version = "v1"
default_action = "deny"
deny_actions = ["filesystem.delete"]
"#,
        )
        .unwrap_or_else(|e| panic!("{e}"));
        let managed = ManagedSeccompPolicyConfig {
            source_policy_path: policy_path,
            artifact_dir: tempdir.path().join("artifacts"),
            verify_checksum: true,
        };
        let err = compile_managed_seccomp(&managed)
            .expect_err("expected unsupported default_action error");
        assert!(
            err.to_string()
                .contains("managed seccomp default_action 'deny' is unsupported"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn sanitize_path_segment_blocks_reserved_dot_segments() {
        assert_eq!(sanitize_path_segment("."), "_");
        assert_eq!(sanitize_path_segment(".."), "_");
        assert_eq!(sanitize_path_segment("..."), "_");
        assert_eq!(sanitize_path_segment("generic-v1"), "generic-v1");
    }
}
