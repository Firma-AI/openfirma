//! Runner for `firma authority`.

use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use firma_authority::{
    AuthorityConfig, CedarPolicyStore, IssuanceRequest, RevocationStore, Server, issue_capability,
    seed::SeedFile,
};
use firma_core::token::paseto::PasetoV4Signer;
use firma_core::{AgentId, SessionId, TokenId};
use pasetors::keys::{AsymmetricKeyPair, Generate};
use pasetors::version4::V4;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, SanType,
};

use crate::args::authority::{Args, Commands, IssueArgs, RevocationsCommand};
use crate::signal::shutdown_future;

/// Run the authority subcommand.
///
/// # Errors
///
/// Propagates any error from configuration loading or subcommand
/// execution.
pub async fn run(args: Args) -> Result<ExitCode> {
    // `generate-key` writes a keypair to an explicit `-o` path and never
    // reads config. Short-circuit before resolution so it works in a
    // bare environment with no discoverable firma.toml.
    if let Some(Commands::GenerateKey { output }) = &args.command {
        run_generate_key(output)?;
        return Ok(ExitCode::SUCCESS);
    }
    if let Some(Commands::InitTls { out_dir, hosts }) = &args.command {
        run_bootstrap_tls(out_dir, hosts)?;
        return Ok(ExitCode::SUCCESS);
    }

    let resolved = firma_config::resolve_config(
        "authority",
        args.config.as_deref(),
        &firma_config::SystemDirs,
    )?;
    tracing::info!(
        path = %resolved.config_file.display(),
        source = ?resolved.source,
        "config resolved"
    );
    let body = firma_config::load_section(&resolved.config_file, "authority")
        .map_err(|e| anyhow::anyhow!("failed to load authority configuration: {e}"))?;
    let tmp_dir = tempfile::tempdir().context("tempdir for authority config")?;
    let tmp_cfg = tmp_dir.path().join("authority.toml");
    std::fs::write(&tmp_cfg, body).context("stage authority config")?;
    let config = AuthorityConfig::load_resolved(&tmp_cfg, &resolved.config_dir)
        .context("failed to load authority configuration")?;

    match args.command {
        None => run_server(config).await?,
        Some(Commands::Revocations {
            action: RevocationsCommand::Add(rargs),
        }) => run_revoke(&config, rargs.token_id, &rargs.reason).await?,
        Some(Commands::Revocations {
            action: RevocationsCommand::Compact,
        }) => run_compact(&config).await?,
        Some(Commands::GenerateKey { output }) => run_generate_key(&output)?,
        Some(Commands::InitTls { out_dir, hosts }) => run_bootstrap_tls(&out_dir, &hosts)?,
        Some(Commands::Issue(iargs)) => run_issue(&config, &iargs).await?,
    }

    Ok(ExitCode::SUCCESS)
}

async fn run_server(config: AuthorityConfig) -> Result<()> {
    let server = Server::try_new(config, shutdown_future())
        .await
        .context("failed to initialize authority server")?;
    server
        .run()
        .await
        .context("authority server exited with error")
}

async fn run_revoke(config: &AuthorityConfig, token_id: TokenId, reason: &str) -> Result<()> {
    let token_ttl = chrono::Duration::seconds(i64::from(config.max_ttl_seconds));
    let store =
        RevocationStore::try_new(&config.revocation_file, token_ttl).with_context(|| {
            format!(
                "failed to open revocation store at {}",
                config.revocation_file.display()
            )
        })?;
    store.revoke(token_id, reason).await.with_context(|| {
        format!(
            "failed to revoke token using store {}",
            config.revocation_file.display()
        )
    })?;
    println!("revoked token: {token_id}");
    Ok(())
}

async fn run_compact(config: &AuthorityConfig) -> Result<()> {
    let token_ttl = chrono::Duration::seconds(i64::from(config.max_ttl_seconds));
    let store =
        RevocationStore::try_new(&config.revocation_file, token_ttl).with_context(|| {
            format!(
                "failed to open revocation store at {}",
                config.revocation_file.display()
            )
        })?;
    store.compact_file().await.with_context(|| {
        format!(
            "failed to compact revocation file {}",
            config.revocation_file.display()
        )
    })?;
    println!("compacted: {}", config.revocation_file.display());
    Ok(())
}

pub fn run_generate_key(path: &std::path::Path) -> Result<()> {
    let mut secret_opts = std::fs::OpenOptions::new();
    secret_opts.create_new(true).write(true);
    let mut public_opts = std::fs::OpenOptions::new();
    public_opts.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        secret_opts.mode(0o600);
        public_opts.mode(0o644);
    }

    let kp = AsymmetricKeyPair::<V4>::generate().context("failed to generate key pair")?;

    let mut private_key_file = secret_opts
        .open(path)
        .context("failed to open output key file")?;
    private_key_file
        .write_all(kp.secret.as_bytes())
        .context("failed to write key file")?;

    let pub_path = path.with_extension("pub");
    let mut pub_key_file = public_opts
        .open(&pub_path)
        .context("failed to open public key file")?;
    pub_key_file
        .write_all(kp.public.as_bytes())
        .context("failed to write public key file")?;

    println!("generated Ed25519 key pair:");
    println!("  secret: {}", path.display());
    println!("  public: {}", pub_path.display());
    Ok(())
}

/// Generate a fresh P-256 ECDSA signing key and write it to `path` in PKCS#8
/// PEM format. Skips if the file already exists and `force` is false.
///
/// # Errors
///
/// Returns an error on key generation failure or I/O error.
pub fn generate_audit_key_if_absent(path: &Path, force: bool) -> Result<()> {
    use p256::ecdsa::SigningKey;
    use p256::elliptic_curve::rand_core::OsRng;
    use p256::pkcs8::EncodePrivateKey as _;
    let key = SigningKey::random(&mut OsRng);
    let pem = key
        .to_pkcs8_pem(p256::pkcs8::LineEnding::default())
        .context("failed to encode audit key as PKCS#8 PEM")?;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true);
    if force {
        // Overwrite unconditionally — truncate any existing file.
        opts.create(true).truncate(true);
    } else {
        // create_new: atomic — fails if another writer raced us to create the file.
        opts.create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    match opts.open(path) {
        Ok(mut file) => file
            .write_all(pem.as_bytes())
            .with_context(|| format!("failed to write {}", path.display())),
        Err(e) if !force && e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e).with_context(|| format!("failed to open {}", path.display())),
    }
}

fn write_new_file(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut file = opts
        .open(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

pub fn run_bootstrap_tls(out_dir: &Path, hosts: &[String]) -> Result<()> {
    let hosts = if hosts.is_empty() {
        vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
            "::1".to_string(),
        ]
    } else {
        hosts.to_vec()
    };

    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("failed to create {}", out_dir.display()))?;

    let ca_cert_path: PathBuf = out_dir.join("authority-ca.crt");
    let ca_key_path: PathBuf = out_dir.join("authority-ca.key");
    let server_cert_path: PathBuf = out_dir.join("authority.crt");
    let server_key_path: PathBuf = out_dir.join("authority.key");

    let ca_key = KeyPair::generate().context("failed to generate CA key pair")?;
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let mut ca_dn = DistinguishedName::new();
    ca_dn.push(DnType::CommonName, "Firma Authority CA");
    ca_params.distinguished_name = ca_dn;
    let ca_cert = ca_params
        .self_signed(&ca_key)
        .context("failed to self-sign CA certificate")?;

    let server_key = KeyPair::generate().context("failed to generate server key pair")?;
    let mut server_params = CertificateParams::default();
    let mut server_dn = DistinguishedName::new();
    server_dn.push(DnType::CommonName, "firma-authority");
    server_params.distinguished_name = server_dn;
    for host in &hosts {
        if let Ok(ip) = host.parse::<IpAddr>() {
            server_params.subject_alt_names.push(SanType::IpAddress(ip));
        } else {
            server_params
                .subject_alt_names
                .push(SanType::DnsName(host.clone().try_into()?));
        }
    }
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .context("failed to sign server certificate with CA")?;

    write_new_file(&ca_cert_path, ca_cert.pem().as_bytes(), 0o644)?;
    write_new_file(&ca_key_path, ca_key.serialize_pem().as_bytes(), 0o600)?;
    write_new_file(&server_cert_path, server_cert.pem().as_bytes(), 0o644)?;
    write_new_file(
        &server_key_path,
        server_key.serialize_pem().as_bytes(),
        0o600,
    )?;

    println!("bootstrapped TLS material:");
    println!("  ca cert : {}", ca_cert_path.display());
    println!("  ca key  : {}", ca_key_path.display());
    println!("  cert    : {}", server_cert_path.display());
    println!("  key     : {}", server_key_path.display());
    println!();
    println!("authority config:");
    println!("  tls_cert_path = \"{}\"", server_cert_path.display());
    println!("  tls_key_path  = \"{}\"", server_key_path.display());
    println!("sidecar config:");
    println!("  authority_url = \"https://{}:50051\"", hosts[0]);
    println!("  ca_cert_path  = \"{}\"", ca_cert_path.display());
    Ok(())
}

async fn run_issue(config: &AuthorityConfig, args: &IssueArgs) -> Result<()> {
    let key_bytes = std::fs::read(&config.key_file)
        .with_context(|| format!("failed to read signing key {}", config.key_file.display()))?;
    let signer = Arc::new(PasetoV4Signer::try_new(&key_bytes).context("invalid signing key")?);
    let policy_store = Arc::new(
        CedarPolicyStore::load(
            &config.policy_dir,
            config.schema_path.clone(),
            config.bundle_ttl_seconds,
        )
        .context("failed to load Cedar policies")?,
    );

    let agent_id: AgentId = args.agent_id.parse().context("invalid agent_id")?;
    let session_id: SessionId = args.session_id.parse().context("invalid session_id")?;
    let req = IssuanceRequest {
        agent_id: &agent_id,
        session_id: &session_id,
        requested_actions: &args.actions,
        resource_scope: &args.resource_scope,
        requested_ttl_seconds: args.ttl_seconds,
    };
    let out = issue_capability(&policy_store, &signer, config.max_ttl_seconds, &req)
        .await
        .map_err(|e| anyhow::anyhow!("issuance failed: {e}"))?;

    let toml_body = SeedFile::from_issuance(&out).to_toml()?;
    std::fs::write(&args.output, toml_body)
        .with_context(|| format!("failed to write {}", args.output.display()))?;
    println!("issued capability to {}", args.output.display());
    Ok(())
}
