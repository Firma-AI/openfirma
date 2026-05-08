//! Runner for `firma authority`.

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

use crate::args::authority::{Args, Commands, IssueArgs, RevocationsCommand};
use crate::signal::shutdown_future;

/// Run the authority subcommand.
///
/// # Errors
///
/// Propagates any error from configuration loading or subcommand
/// execution.
pub async fn run(args: Args) -> Result<ExitCode> {
    let config = AuthorityConfig::load(args.config.as_ref())
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

fn run_generate_key(output: &std::path::Path) -> Result<()> {
    let kp = AsymmetricKeyPair::<V4>::generate().context("failed to generate key pair")?;

    std::fs::write(output, kp.secret.as_bytes())
        .with_context(|| format!("failed to write key file {}", output.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        if let Err(e) = std::fs::set_permissions(output, perms) {
            eprintln!("warning: could not set key file permissions: {e}");
        }
    }

    let pub_path = output.with_extension("pub");
    std::fs::write(&pub_path, kp.public.as_bytes())
        .with_context(|| format!("failed to write public key file {}", pub_path.display()))?;

    println!("generated Ed25519 key pair:");
    println!("  secret: {}", output.display());
    println!("  public: {}", pub_path.display());
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
