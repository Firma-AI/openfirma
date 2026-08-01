use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::fs::File;
use std::io::{ErrorKind, Write};
#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::Utc;
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule, TargetArch};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::{ResolvedProfile, SeccompPolicyConfig, SeccompRuntimeMode};
use crate::error::RunError;

const COMPILER_VERSION: &str = "managed-seccomp-v2-seccompiler";
const POLICY_SCHEMA_VERSION: u32 = 1;
const EPERM_ERRNO: u32 = 1;

/// Runtime seccomp materialization outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeccompMaterialized {
    pub(crate) bpf_path: PathBuf,
    metadata_path: PathBuf,
    pub(crate) metadata: SeccompArtifactMetadata,
}

/// Resolve the effective seccomp filter for a profile.
///
/// Managed policy mode compiles a deterministic artifact and returns the
/// generated filter path.
///
/// # Errors
///
/// Returns an error when managed policy compilation, artifact write, or
/// checksum verification fails.
pub(crate) fn resolve_effective_seccomp(
    profile: &ResolvedProfile,
) -> Result<Option<SeccompMaterialized>, RunError> {
    let Some(managed) = &profile.seccomp_policy else {
        return Ok(None);
    };

    let generated = materialize_seccomp_policy(managed)?;
    Ok(Some(generated))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct SeccompArtifactMetadata {
    policy_schema_version: u32,
    pub(crate) policy_id: String,
    pub(crate) policy_version: String,
    pub(crate) sha256: String,
    generated_at: String,
    pub(crate) compiler_version: String,
    pub(crate) target_arch: String,
    default_action: String,
    source_policy_refs: Vec<String>,
    source_policy_sha256: String,
    denied_syscalls: Vec<String>,
}

/// `seccompiler::TargetArch` has no string representation; the artifact
/// metadata and artifact directory layout need one.
fn target_arch_str(target_arch: TargetArch) -> &'static str {
    match target_arch {
        TargetArch::x86_64 => "x86_64",
        TargetArch::aarch64 => "aarch64",
        TargetArch::riscv64 => "riscv64",
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

    fn number_for_arch(self, target_arch: TargetArch) -> Option<i64> {
        match target_arch {
            TargetArch::x86_64 => match self {
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
            TargetArch::aarch64 => match self {
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
            // The managed seccomp baseline only targets x86_64 and aarch64;
            // current_target_arch() rejects every other host before this is reached.
            TargetArch::riscv64 => None,
        }
    }
}

fn default_policy_action() -> String {
    "allow".to_string()
}

#[derive(Debug, Clone)]
struct ParsedPolicy {
    parsed: CedarSubsetPolicyFile,
    source_policy_sha256: String,
}

fn materialize_seccomp_policy(
    managed: &SeccompPolicyConfig,
) -> Result<SeccompMaterialized, RunError> {
    if !cfg!(target_os = "linux") {
        return Err(RunError::ConfigValidation(
            "seccomp policy is supported only on Linux hosts".to_string(),
        ));
    }

    let target_arch = current_target_arch()?;
    let parsed_policy = parse_policy_source(&managed.source_policy_path)?;
    validate_policy_source(&parsed_policy.parsed)?;
    let (syscalls, unsupported_actions) =
        map_actions_to_syscalls(&parsed_policy.parsed.deny_actions);
    if !unsupported_actions.is_empty() {
        return Err(RunError::ConfigValidation(format!(
            "seccomp policy contains unsupported Cedar actions: {}; supported deny actions are: system.execute, filesystem.delete, credential.write",
            unsupported_actions.join(", ")
        )));
    }
    let expected_denied_syscalls = expected_denied_syscalls(target_arch, &syscalls);
    let output_dir = managed.artifact_dir.join(artifact_relative_dir(
        &parsed_policy.parsed.policy_id,
        &parsed_policy.parsed.policy_version,
        target_arch,
    ));
    let bpf_path = output_dir.join("policy.bpf");
    let metadata_path = output_dir.join("policy.metadata.json");

    match managed.runtime_mode {
        SeccompRuntimeMode::CompileOnLaunch => compile_and_write_artifact(
            managed,
            target_arch,
            &parsed_policy,
            &syscalls,
            &expected_denied_syscalls,
            bpf_path,
            metadata_path,
        ),
        SeccompRuntimeMode::PrecompiledOnly => load_precompiled_artifact(
            managed,
            target_arch,
            &parsed_policy,
            &expected_denied_syscalls,
            bpf_path,
            metadata_path,
        ),
    }
}

fn parse_policy_source(path: &Path) -> Result<ParsedPolicy, RunError> {
    let policy_src = fs::read_to_string(path).map_err(|error| {
        RunError::ConfigValidation(format!(
            "failed to read seccomp policy {}: {error}",
            path.display()
        ))
    })?;
    let parsed: CedarSubsetPolicyFile = toml::from_str(&policy_src).map_err(|error| {
        RunError::ConfigValidation(format!(
            "invalid seccomp policy {}: {error}",
            path.display()
        ))
    })?;
    Ok(ParsedPolicy {
        parsed,
        source_policy_sha256: sha256_hex(policy_src.as_bytes()),
    })
}

fn validate_policy_source(parsed: &CedarSubsetPolicyFile) -> Result<(), RunError> {
    if parsed.policy_id.trim().is_empty() {
        return Err(RunError::ConfigValidation(
            "seccomp policy_id must not be empty".to_string(),
        ));
    }
    if parsed.policy_version.trim().is_empty() {
        return Err(RunError::ConfigValidation(
            "seccomp policy_version must not be empty".to_string(),
        ));
    }
    if parsed.default_action != "allow" {
        return Err(RunError::ConfigValidation(format!(
            "seccomp policy default_action '{}' is unsupported; only 'allow' is currently supported",
            parsed.default_action
        )));
    }
    Ok(())
}

fn compile_and_write_artifact(
    managed: &SeccompPolicyConfig,
    target_arch: TargetArch,
    parsed_policy: &ParsedPolicy,
    syscalls: &[SyscallId],
    expected_denied_syscalls: &[String],
    bpf_path: PathBuf,
    metadata_path: PathBuf,
) -> Result<SeccompMaterialized, RunError> {
    fs::create_dir_all(
        bpf_path
            .parent()
            .ok_or_else(|| RunError::Internal("seccomp artifact parent dir missing".to_string()))?,
    )
    .map_err(|error| {
        RunError::ConfigValidation(format!(
            "failed to create seccomp artifact dir {}: {error}",
            bpf_path
                .parent()
                .map_or_else(|| "<unknown>".to_string(), |p| p.display().to_string())
        ))
    })?;

    let (bpf_bytes, effective_syscalls) = compile_bpf_program(target_arch, syscalls)?;
    let bpf_sha = sha256_hex(&bpf_bytes);

    write_atomic(&bpf_path, &bpf_bytes)?;

    let metadata = SeccompArtifactMetadata {
        policy_schema_version: POLICY_SCHEMA_VERSION,
        policy_id: parsed_policy.parsed.policy_id.clone(),
        policy_version: parsed_policy.parsed.policy_version.clone(),
        sha256: bpf_sha,
        generated_at: Utc::now().to_rfc3339(),
        compiler_version: COMPILER_VERSION.to_string(),
        target_arch: target_arch_str(target_arch).to_string(),
        default_action: parsed_policy.parsed.default_action.clone(),
        source_policy_refs: if parsed_policy.parsed.source_policy_refs.is_empty() {
            vec![managed.source_policy_path.display().to_string()]
        } else {
            parsed_policy.parsed.source_policy_refs.clone()
        },
        source_policy_sha256: parsed_policy.source_policy_sha256.clone(),
        denied_syscalls: effective_syscalls,
    };
    let metadata_bytes = serde_json::to_vec_pretty(&metadata).map_err(|error| {
        RunError::Internal(format!("failed to serialize seccomp metadata: {error}"))
    })?;
    write_atomic(&metadata_path, &metadata_bytes)?;

    verify_artifact_trust_paths(managed, &bpf_path, &metadata_path)?;
    validate_metadata_contract(
        &metadata,
        target_arch,
        &parsed_policy.parsed,
        &parsed_policy.source_policy_sha256,
        expected_denied_syscalls,
    )?;
    verify_artifact_checksum(&bpf_path, &metadata)?;

    Ok(SeccompMaterialized {
        bpf_path,
        metadata_path,
        metadata,
    })
}

fn load_precompiled_artifact(
    managed: &SeccompPolicyConfig,
    target_arch: TargetArch,
    parsed_policy: &ParsedPolicy,
    expected_denied_syscalls: &[String],
    bpf_path: PathBuf,
    metadata_path: PathBuf,
) -> Result<SeccompMaterialized, RunError> {
    let metadata = read_metadata(&metadata_path)?;
    verify_artifact_trust_paths(managed, &bpf_path, &metadata_path)?;
    validate_metadata_contract(
        &metadata,
        target_arch,
        &parsed_policy.parsed,
        &parsed_policy.source_policy_sha256,
        expected_denied_syscalls,
    )?;
    verify_artifact_checksum(&bpf_path, &metadata)?;
    Ok(SeccompMaterialized {
        bpf_path,
        metadata_path,
        metadata,
    })
}

fn artifact_relative_dir(policy_id: &str, policy_version: &str, target_arch: TargetArch) -> String {
    format!(
        "{}/{}/{}",
        sanitize_path_segment(policy_id),
        sanitize_path_segment(policy_version),
        target_arch_str(target_arch)
    )
}

fn expected_denied_syscalls(target_arch: TargetArch, syscalls: &[SyscallId]) -> Vec<String> {
    syscalls
        .iter()
        .copied()
        .filter(|syscall| syscall.number_for_arch(target_arch).is_some())
        .map(SyscallId::name)
        .map(str::to_string)
        .collect()
}

fn read_metadata(metadata_path: &Path) -> Result<SeccompArtifactMetadata, RunError> {
    let metadata_bytes = fs::read(metadata_path).map_err(|error| {
        RunError::ConfigValidation(format!(
            "failed to read seccomp metadata {}: {error}",
            metadata_path.display()
        ))
    })?;
    serde_json::from_slice(&metadata_bytes).map_err(|error| {
        RunError::ConfigValidation(format!(
            "failed to parse seccomp metadata {}: {error}",
            metadata_path.display()
        ))
    })
}

fn validate_metadata_contract(
    metadata: &SeccompArtifactMetadata,
    target_arch: TargetArch,
    parsed_policy: &CedarSubsetPolicyFile,
    source_policy_sha256: &str,
    expected_denied_syscalls: &[String],
) -> Result<(), RunError> {
    if metadata.policy_schema_version != POLICY_SCHEMA_VERSION {
        return Err(RunError::ConfigValidation(format!(
            "seccomp metadata policy_schema_version mismatch: expected {}, got {}",
            POLICY_SCHEMA_VERSION, metadata.policy_schema_version
        )));
    }
    if metadata.policy_id != parsed_policy.policy_id {
        return Err(RunError::ConfigValidation(format!(
            "seccomp metadata policy_id mismatch: expected '{}', got '{}'",
            parsed_policy.policy_id, metadata.policy_id
        )));
    }
    if metadata.policy_version != parsed_policy.policy_version {
        return Err(RunError::ConfigValidation(format!(
            "seccomp metadata policy_version mismatch: expected '{}', got '{}'",
            parsed_policy.policy_version, metadata.policy_version
        )));
    }
    if metadata.default_action != parsed_policy.default_action {
        return Err(RunError::ConfigValidation(format!(
            "seccomp metadata default_action mismatch: expected '{}', got '{}'",
            parsed_policy.default_action, metadata.default_action
        )));
    }
    if metadata.target_arch != target_arch_str(target_arch) {
        return Err(RunError::ConfigValidation(format!(
            "seccomp metadata target_arch mismatch: expected '{}', got '{}'",
            target_arch_str(target_arch),
            metadata.target_arch
        )));
    }
    if metadata.compiler_version.trim().is_empty() {
        return Err(RunError::ConfigValidation(
            "seccomp metadata compiler_version must not be empty".to_string(),
        ));
    }
    if metadata.generated_at.trim().is_empty() {
        return Err(RunError::ConfigValidation(
            "seccomp metadata generated_at must not be empty".to_string(),
        ));
    }
    if metadata.source_policy_refs.is_empty() {
        return Err(RunError::ConfigValidation(
            "seccomp metadata source_policy_refs must not be empty".to_string(),
        ));
    }
    if metadata.source_policy_sha256 != source_policy_sha256 {
        return Err(RunError::ConfigValidation(format!(
            "seccomp metadata source_policy_sha256 mismatch: expected {}, got {}",
            source_policy_sha256, metadata.source_policy_sha256
        )));
    }
    if metadata.denied_syscalls != expected_denied_syscalls {
        return Err(RunError::ConfigValidation(format!(
            "seccomp metadata denied_syscalls mismatch: expected {:?}, got {:?}",
            expected_denied_syscalls, metadata.denied_syscalls
        )));
    }
    if !is_valid_sha256_hex(&metadata.sha256) {
        return Err(RunError::ConfigValidation(format!(
            "seccomp metadata sha256 is invalid: {}",
            metadata.sha256
        )));
    }
    Ok(())
}

fn is_valid_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit())
}

fn verify_artifact_checksum(
    bpf_path: &Path,
    metadata: &SeccompArtifactMetadata,
) -> Result<(), RunError> {
    let file_bytes = fs::read(bpf_path).map_err(|error| {
        RunError::ConfigValidation(format!(
            "failed to read seccomp artifact {}: {error}",
            bpf_path.display()
        ))
    })?;
    let actual_sha = sha256_hex(&file_bytes);
    if actual_sha != metadata.sha256 {
        return Err(RunError::ConfigValidation(format!(
            "seccomp checksum mismatch for {}: expected {}, got {}",
            bpf_path.display(),
            metadata.sha256,
            actual_sha
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_artifact_trust_paths(
    managed: &SeccompPolicyConfig,
    bpf_path: &Path,
    metadata_path: &Path,
) -> Result<(), RunError> {
    let leaf_dir = bpf_path.parent().ok_or_else(|| {
        RunError::ConfigValidation("seccomp artifact leaf directory is missing".to_string())
    })?;
    let current_uid = current_runtime_uid()?;

    verify_secure_dir(&managed.artifact_dir, current_uid, "seccomp artifact_dir")?;
    verify_secure_dir(leaf_dir, current_uid, "seccomp artifact leaf directory")?;
    verify_secure_file(bpf_path, current_uid, "seccomp artifact")?;
    verify_secure_file(metadata_path, current_uid, "seccomp metadata")?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn current_runtime_uid() -> Result<u32, RunError> {
    fs::metadata("/proc/self")
        .map(|meta| meta.uid())
        .map_err(|error| {
            RunError::ConfigValidation(format!(
                "failed to resolve runtime uid from /proc/self: {error}"
            ))
        })
}

#[cfg(not(target_os = "linux"))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "non-linux stub preserves the linux Result-based interface"
)]
fn verify_artifact_trust_paths(
    _managed: &SeccompPolicyConfig,
    _bpf_path: &Path,
    _metadata_path: &Path,
) -> Result<(), RunError> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_secure_dir(path: &Path, current_uid: u32, label: &str) -> Result<(), RunError> {
    let meta = read_non_symlink(path, label)?;
    if !meta.is_dir() {
        return Err(RunError::ConfigValidation(format!(
            "{label} must be a directory: {}",
            path.display()
        )));
    }
    verify_owner_and_mode(path, label, current_uid, meta.uid(), meta.mode())
}

#[cfg(target_os = "linux")]
fn verify_secure_file(path: &Path, current_uid: u32, label: &str) -> Result<(), RunError> {
    let meta = read_non_symlink(path, label)?;
    if !meta.is_file() {
        return Err(RunError::ConfigValidation(format!(
            "{label} must be a regular file: {}",
            path.display()
        )));
    }
    verify_owner_and_mode(path, label, current_uid, meta.uid(), meta.mode())
}

#[cfg(target_os = "linux")]
fn read_non_symlink(path: &Path, label: &str) -> Result<std::fs::Metadata, RunError> {
    let symlink_meta = fs::symlink_metadata(path).map_err(|error| {
        RunError::ConfigValidation(format!(
            "failed to stat {label} {}: {error}",
            path.display()
        ))
    })?;
    if symlink_meta.file_type().is_symlink() {
        return Err(RunError::ConfigValidation(format!(
            "{label} must not be a symlink: {}",
            path.display()
        )));
    }
    Ok(symlink_meta)
}

#[cfg(target_os = "linux")]
fn verify_owner_and_mode(
    path: &Path,
    label: &str,
    current_uid: u32,
    owner_uid: u32,
    mode: u32,
) -> Result<(), RunError> {
    if owner_uid != current_uid {
        return Err(RunError::ConfigValidation(format!(
            "{label} owner mismatch for {}: expected uid {}, got uid {}",
            path.display(),
            current_uid,
            owner_uid
        )));
    }
    let perms = mode & 0o777;
    if perms & 0o002 != 0 {
        return Err(RunError::ConfigValidation(format!(
            "{label} has insecure permissions for {}: mode {:o}; other-write bit is forbidden",
            path.display(),
            perms
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
        .map_or(0, |d| d.as_nanos());

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
        if let Some(parent) = path.parent()
            && let Err(error) = sync_parent_dir(parent)
        {
            return Err(RunError::ConfigValidation(format!(
                "failed to sync parent dir {}: {error}",
                parent.display()
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

fn sync_parent_dir(path: &Path) -> Result<(), std::io::Error> {
    let dir = File::open(path)?;
    dir.sync_all()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    hex::encode(digest)
}

fn current_target_arch() -> Result<TargetArch, RunError> {
    if cfg!(target_arch = "x86_64") {
        return Ok(TargetArch::x86_64);
    }
    if cfg!(target_arch = "aarch64") {
        return Ok(TargetArch::aarch64);
    }
    Err(RunError::ConfigValidation(
        "seccomp policy supports only x86_64 and aarch64 targets".to_string(),
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

/// Compiles the managed deny-list into a raw classic-BPF program via
/// `seccompiler`, in the exact byte layout the kernel (and `bwrap --seccomp
/// <fd>`) expects: a flat array of `struct sock_filter` (u16 code, u8 jt,
/// u8 jf, u32 k, native endian), with no framing.
fn compile_bpf_program(
    target_arch: TargetArch,
    denied_syscalls: &[SyscallId],
) -> Result<(Vec<u8>, Vec<String>), RunError> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    let mut effective_syscalls = Vec::new();

    for syscall in denied_syscalls {
        let Some(nr) = syscall.number_for_arch(target_arch) else {
            continue;
        };
        rules.insert(nr, Vec::new());
        effective_syscalls.push(syscall.name().to_string());
    }

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(EPERM_ERRNO),
        target_arch,
    )
    .map_err(|error| RunError::Internal(format!("failed to build seccomp filter: {error}")))?;
    let bpf_program: BpfProgram = filter.try_into().map_err(|error| {
        RunError::Internal(format!("failed to compile seccomp filter to BPF: {error}"))
    })?;

    Ok((bpf_program_to_bytes(&bpf_program), effective_syscalls))
}

fn bpf_program_to_bytes(program: &BpfProgram) -> Vec<u8> {
    let mut out = Vec::with_capacity(program.len() * 8);
    for insn in program {
        out.extend_from_slice(&insn.code.to_ne_bytes());
        out.push(insn.jt);
        out.push(insn.jf);
        out.extend_from_slice(&insn.k.to_ne_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    use std::os::unix::fs::{PermissionsExt, symlink};

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
    #[cfg(target_os = "linux")]
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
        let managed = SeccompPolicyConfig {
            source_policy_path: policy_path,
            artifact_dir: artifacts,
            verify_checksum: true,
            runtime_mode: SeccompRuntimeMode::CompileOnLaunch,
        };

        let out = materialize_seccomp_policy(&managed).unwrap_or_else(|e| panic!("{e}"));
        assert!(out.bpf_path.is_file());
        assert!(out.metadata_path.is_file());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn compile_on_launch_is_reproducible_for_same_policy_and_arch() {
        let tempdir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let policy_path = tempdir.path().join("policy.toml");
        fs::write(
            &policy_path,
            r#"
policy_id = "generic-local-command"
policy_version = "v1"
default_action = "allow"
deny_actions = ["filesystem.delete", "credential.write"]
"#,
        )
        .unwrap_or_else(|e| panic!("{e}"));
        let artifacts = tempdir.path().join("artifacts");
        let managed = SeccompPolicyConfig {
            source_policy_path: policy_path,
            artifact_dir: artifacts,
            verify_checksum: true,
            runtime_mode: SeccompRuntimeMode::CompileOnLaunch,
        };

        let out_a = materialize_seccomp_policy(&managed).unwrap_or_else(|e| panic!("{e}"));
        let bytes_a = fs::read(&out_a.bpf_path).unwrap_or_else(|e| panic!("{e}"));
        let out_b = materialize_seccomp_policy(&managed).unwrap_or_else(|e| panic!("{e}"));
        let bytes_b = fs::read(&out_b.bpf_path).unwrap_or_else(|e| panic!("{e}"));

        assert_eq!(bytes_a, bytes_b, "bpf bytes must be deterministic");
        assert_eq!(
            out_a.metadata.sha256, out_b.metadata.sha256,
            "artifact checksums must be deterministic"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
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
        let managed = SeccompPolicyConfig {
            source_policy_path: policy_path,
            artifact_dir: artifacts,
            verify_checksum: true,
            runtime_mode: SeccompRuntimeMode::CompileOnLaunch,
        };

        let out = materialize_seccomp_policy(&managed).unwrap_or_else(|e| panic!("{e}"));
        fs::write(&out.bpf_path, [1_u8, 2, 3, 4]).unwrap_or_else(|e| panic!("{e}"));

        let err = verify_artifact_checksum(&out.bpf_path, &out.metadata)
            .expect_err("expected checksum mismatch");
        assert!(
            err.to_string().contains("seccomp checksum mismatch"),
            "unexpected error: {err}"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn fails_when_policy_source_missing() {
        let tempdir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let managed = SeccompPolicyConfig {
            source_policy_path: tempdir.path().join("missing.toml"),
            artifact_dir: tempdir.path().join("artifacts"),
            verify_checksum: true,
            runtime_mode: SeccompRuntimeMode::CompileOnLaunch,
        };
        let err =
            materialize_seccomp_policy(&managed).expect_err("expected missing policy failure");
        assert!(
            err.to_string().contains("failed to read seccomp policy"),
            "unexpected error: {err}"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
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
        let managed = SeccompPolicyConfig {
            source_policy_path: policy_path,
            artifact_dir: tempdir.path().join("artifacts"),
            verify_checksum: true,
            runtime_mode: SeccompRuntimeMode::CompileOnLaunch,
        };
        let err =
            materialize_seccomp_policy(&managed).expect_err("expected unsupported action error");
        assert!(
            err.to_string()
                .contains("seccomp policy contains unsupported Cedar actions"),
            "unexpected error: {err}"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
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
        let managed = SeccompPolicyConfig {
            source_policy_path: policy_path,
            artifact_dir: tempdir.path().join("artifacts"),
            verify_checksum: true,
            runtime_mode: SeccompRuntimeMode::CompileOnLaunch,
        };
        let err = materialize_seccomp_policy(&managed)
            .expect_err("expected unsupported default_action error");
        assert!(
            err.to_string()
                .contains("seccomp policy default_action 'deny' is unsupported"),
            "unexpected error: {err}"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn precompiled_mode_fails_when_artifact_missing() {
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
        let managed = SeccompPolicyConfig {
            source_policy_path: policy_path,
            artifact_dir: tempdir.path().join("artifacts"),
            verify_checksum: true,
            runtime_mode: SeccompRuntimeMode::PrecompiledOnly,
        };
        let err = materialize_seccomp_policy(&managed)
            .expect_err("expected missing precompiled artifact");
        assert!(
            err.to_string().contains("failed to read seccomp metadata"),
            "unexpected error: {err}"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn precompiled_mode_fails_on_invalid_metadata_format() {
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

        let arch = current_target_arch().unwrap_or_else(|e| panic!("{e}"));
        let out_dir =
            tempdir
                .path()
                .join(artifact_relative_dir("generic-local-command", "v1", arch));
        fs::create_dir_all(&out_dir).unwrap_or_else(|e| panic!("{e}"));
        fs::write(out_dir.join("policy.bpf"), [0_u8; 16]).unwrap_or_else(|e| panic!("{e}"));
        fs::write(out_dir.join("policy.metadata.json"), b"{not-json")
            .unwrap_or_else(|e| panic!("{e}"));

        let managed = SeccompPolicyConfig {
            source_policy_path: policy_path,
            artifact_dir: tempdir.path().to_path_buf(),
            verify_checksum: true,
            runtime_mode: SeccompRuntimeMode::PrecompiledOnly,
        };
        let err =
            materialize_seccomp_policy(&managed).expect_err("expected invalid metadata parse");
        assert!(
            err.to_string().contains("failed to parse seccomp metadata"),
            "unexpected error: {err}"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn precompiled_mode_fails_on_checksum_mismatch() {
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
        let artifact_dir = tempdir.path().join("artifacts");

        let compile_mode = SeccompPolicyConfig {
            source_policy_path: policy_path.clone(),
            artifact_dir: artifact_dir.clone(),
            verify_checksum: true,
            runtime_mode: SeccompRuntimeMode::CompileOnLaunch,
        };
        let compiled = materialize_seccomp_policy(&compile_mode).unwrap_or_else(|e| panic!("{e}"));
        fs::write(&compiled.bpf_path, [9_u8, 8, 7, 6]).unwrap_or_else(|e| panic!("{e}"));

        let precompiled_mode = SeccompPolicyConfig {
            source_policy_path: policy_path,
            artifact_dir,
            verify_checksum: true,
            runtime_mode: SeccompRuntimeMode::PrecompiledOnly,
        };
        let err = materialize_seccomp_policy(&precompiled_mode)
            .expect_err("expected checksum mismatch in precompiled mode");
        assert!(
            err.to_string().contains("seccomp checksum mismatch"),
            "unexpected error: {err}"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn precompiled_mode_fails_on_metadata_contract_mismatch() {
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
        let artifact_dir = tempdir.path().join("artifacts");

        let compile_mode = SeccompPolicyConfig {
            source_policy_path: policy_path.clone(),
            artifact_dir: artifact_dir.clone(),
            verify_checksum: true,
            runtime_mode: SeccompRuntimeMode::CompileOnLaunch,
        };
        let compiled = materialize_seccomp_policy(&compile_mode).unwrap_or_else(|e| panic!("{e}"));

        let mut mutated = compiled.metadata.clone();
        mutated.denied_syscalls = vec!["openat".to_string()];
        let mutated_json = serde_json::to_vec_pretty(&mutated).unwrap_or_else(|e| panic!("{e}"));
        fs::write(&compiled.metadata_path, mutated_json).unwrap_or_else(|e| panic!("{e}"));

        let precompiled_mode = SeccompPolicyConfig {
            source_policy_path: policy_path,
            artifact_dir,
            verify_checksum: true,
            runtime_mode: SeccompRuntimeMode::PrecompiledOnly,
        };
        let err = materialize_seccomp_policy(&precompiled_mode)
            .expect_err("expected metadata contract mismatch");
        assert!(
            err.to_string()
                .contains("seccomp metadata denied_syscalls mismatch"),
            "unexpected error: {err}"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn precompiled_mode_rejects_group_writable_artifact_dir() {
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
        let artifact_dir = tempdir.path().join("artifacts");

        let compile_mode = SeccompPolicyConfig {
            source_policy_path: policy_path.clone(),
            artifact_dir: artifact_dir.clone(),
            verify_checksum: true,
            runtime_mode: SeccompRuntimeMode::CompileOnLaunch,
        };
        let compiled = materialize_seccomp_policy(&compile_mode).unwrap_or_else(|e| panic!("{e}"));
        let leaf_dir = compiled
            .bpf_path
            .parent()
            .unwrap_or_else(|| panic!("missing artifact leaf dir"));

        fs::set_permissions(leaf_dir, std::fs::Permissions::from_mode(0o777))
            .unwrap_or_else(|e| panic!("{e}"));
        let precompiled_mode = SeccompPolicyConfig {
            source_policy_path: policy_path,
            artifact_dir,
            verify_checksum: true,
            runtime_mode: SeccompRuntimeMode::PrecompiledOnly,
        };
        let err = materialize_seccomp_policy(&precompiled_mode)
            .expect_err("expected permissions hardening failure");
        assert!(
            err.to_string().contains("insecure permissions"),
            "unexpected error: {err}"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn precompiled_mode_rejects_symlinked_metadata_file() {
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
        let good_artifact_dir = tempdir.path().join("artifacts-good");

        let compile_mode = SeccompPolicyConfig {
            source_policy_path: policy_path.clone(),
            artifact_dir: good_artifact_dir,
            verify_checksum: true,
            runtime_mode: SeccompRuntimeMode::CompileOnLaunch,
        };
        let compiled = materialize_seccomp_policy(&compile_mode).unwrap_or_else(|e| panic!("{e}"));

        let bad_artifact_dir = tempdir.path().join("artifacts-bad");
        let arch = current_target_arch().unwrap_or_else(|e| panic!("{e}"));
        let rel = artifact_relative_dir("generic-local-command", "v1", arch);
        let bad_leaf = bad_artifact_dir.join(rel);
        fs::create_dir_all(&bad_leaf).unwrap_or_else(|e| panic!("{e}"));
        fs::copy(&compiled.bpf_path, bad_leaf.join("policy.bpf")).unwrap_or_else(|e| panic!("{e}"));
        symlink(
            &compiled.metadata_path,
            bad_leaf.join("policy.metadata.json"),
        )
        .unwrap_or_else(|e| panic!("{e}"));

        let precompiled_mode = SeccompPolicyConfig {
            source_policy_path: policy_path,
            artifact_dir: bad_artifact_dir,
            verify_checksum: true,
            runtime_mode: SeccompRuntimeMode::PrecompiledOnly,
        };
        let err = materialize_seccomp_policy(&precompiled_mode)
            .expect_err("expected symlink hardening failure");
        assert!(
            err.to_string().contains("must not be a symlink"),
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

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn seccomp_policy_compile_rejected_on_non_linux() {
        let managed = SeccompPolicyConfig {
            source_policy_path: PathBuf::from("/tmp/unused.toml"),
            artifact_dir: PathBuf::from("/tmp/artifacts"),
            verify_checksum: true,
            runtime_mode: SeccompRuntimeMode::CompileOnLaunch,
        };
        let err = materialize_seccomp_policy(&managed).expect_err("expected non-linux rejection");
        assert!(
            err.to_string()
                .contains("seccomp policy is supported only on Linux hosts"),
            "unexpected error: {err}"
        );
    }
}
