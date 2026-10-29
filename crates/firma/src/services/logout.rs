use std::process::ExitCode;

use anyhow::Context as _;
use firma_connection_store::{ConnectionStore, Durability, Removed, SavedConnection};
use firma_login::{ControlPlaneOrigin, NativeTokenClient};

/// Attempts Control Plane revocation, then removes local authority regardless.
///
/// # Errors
///
/// Returns an error when the connection directory is unsafe or the connection
/// cannot be removed. Remote revocation failures are warnings because local
/// removal is still attempted and completes logout on this machine.
pub async fn run() -> anyhow::Result<ExitCode> {
    let Some(store) = ConnectionStore::open_existing(firma_connection_store::default_dir()?)
        .context("could not open the saved login")?
    else {
        println!("No saved login.");
        return Ok(ExitCode::SUCCESS);
    };
    let guard = store
        .exclusive()
        .context("could not lock the saved login")?;
    // The lock prevents a concurrent refresh from rotating between revocation
    // and removal. Failure to read or revoke does not prevent local logout.
    let saved = guard.load();
    let revocation = match saved {
        Ok(Some(saved)) if saved.secret.secret().is_some() => revoke_saved(saved).await.err(),
        Ok(_) => None,
        Err(error) => Some(
            anyhow::Error::new(error)
                .context("the renewable credential could not be read for server revocation"),
        ),
    };
    let removed = guard.remove().context("could not remove the saved login")?;
    match removed {
        Removed::Nothing => println!("No saved login."),
        Removed::Existing {
            durability,
            stale_secret_left,
        } => {
            println!("Logged out.");
            if stale_secret_left {
                eprintln!(
                    "Warning: a credential for the previous login may remain in the operating system credential store."
                );
            }
            if durability == Durability::Uncertain {
                eprintln!("Warning: the local logout may not survive a system crash.");
            }
            if let Some(error) = revocation {
                eprintln!(
                    "Warning: the renewable login was removed locally, but server revocation was not confirmed: {error:#}"
                );
            }
        }
        _ => eprintln!("Warning: the saved login returned an unknown removal result."),
    }
    Ok(ExitCode::SUCCESS)
}

async fn revoke_saved(saved: SavedConnection) -> anyhow::Result<()> {
    let origin = ControlPlaneOrigin::saved(&saved.connection)
        .context("the saved control-plane origin is invalid")?;
    let client = NativeTokenClient::new(&origin).context("could not prepare server revocation")?;
    let secret = saved
        .secret
        .secret()
        .context("the renewable credential is missing")?;
    client
        .revoke(secret.as_secret())
        .await
        .context("server revocation failed")
}
