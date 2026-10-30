use std::io::{self, IsTerminal as _};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::Context as _;
use firma_connection_store::{
    Backend, Connection, ConnectionSecret, ConnectionStore, Durability, OriginMode, Replaced,
    SecretPolicy,
};
use firma_login::{
    AuthorizationAttempt, AuthorizationRequest, AuthorizationScope, AuthorizedTokenExchange,
    CallbackWaitTimeout, ControlPlaneOrigin, NativeTokenClient, OriginValidationMode,
    TerminalAuthorizationRequest, print_and_open,
};
use zeroize::Zeroizing;

use crate::args::login::Args;
use crate::services::terminal_mode;

/// How long the CLI waits for the browser's callback or a pasted code: the
/// time to sign in and approve, and with terminal delivery to paste the code,
/// which works for 10 minutes from approval. The
/// Authority stays the judge: a code past its attempt is `invalid_grant`.
const CALLBACK_DEADLINE: Duration = Duration::from_mins(15);

struct AuthenticatedLogin {
    connection: Connection,
    refresh: Option<ConnectionSecret>,
    policy: SecretPolicy,
}

struct SavedLogin {
    dir: std::path::PathBuf,
    replaced: Replaced,
}

/// Runs one login. Ctrl-C ends authentication even while the hidden prompt
/// has echo turned off. Once authenticated, the local save completes.
///
/// A blocked prompt read cannot be cancelled: returning drops the login and
/// its secrets, and `main` does not wait for that read at exit.
pub async fn run(args: Args) -> anyhow::Result<ExitCode> {
    // Saved before the prompt can turn echo off, which it would restore only
    // after reading a line.
    let terminal = (args.terminal_code && io::stdin().is_terminal())
        .then(terminal_mode::save)
        .transpose()
        .context("could not read terminal settings")?;
    let interrupt = tokio::signal::ctrl_c();
    tokio::pin!(interrupt);
    let authenticated = tokio::select! {
        // Polled first, so the handler is installed before the prompt starts.
        biased;
        _ = &mut interrupt => {
            terminal_mode::restore_or_warn(terminal.as_ref());
            eprintln!();
            // 130, as a shell reports SIGINT.
            return Ok(ExitCode::from(130));
        }
        result = authenticate(args) => result,
    };
    if authenticated
        .as_ref()
        .is_err_and(anyhow::Error::is::<PromptExpired>)
    {
        terminal_mode::restore_or_warn(terminal.as_ref());
        eprintln!();
    }
    let authenticated = authenticated?;
    let workspace_id = authenticated.connection.workspace_id;
    let membership_id = authenticated.connection.membership_id;
    let origin = authenticated.connection.origin.clone();
    eprintln!("Saving this login...");
    // Once authentication succeeds, finish the local commit even if Ctrl-C
    // arrives. A blocking save cannot be cancelled after it starts, so tell
    // the caller that an interruption must wait for its outcome.
    let saving = save(authenticated);
    tokio::pin!(saving);
    let saved = tokio::select! {
        result = &mut saving => result,
        _ = &mut interrupt => {
            eprintln!("Finishing the local save; please wait.");
            saving.await
        }
    }
    .context("could not save the login")?;
    println!("Logged in to Workspace {workspace_id} as Membership {membership_id}.");
    println!("Saved this login to {}.", saved.dir.display());
    // What to run next: the handle is chosen per Agent, so it stays a placeholder.
    println!("Next: firma run --agent <agent handle> -- <your agent command>");
    println!(
        "Agent handles are on the Agents page at {}.",
        origin.as_str().trim_end_matches('/')
    );
    match saved.replaced.backend {
        Backend::None => {}
        Backend::Native => eprintln!("Credential saved in the operating system credential store."),
        Backend::File => eprintln!("Warning: the credential was saved in a local file."),
        _ => eprintln!("Warning: the credential backend is not recognized."),
    }
    if saved.replaced.stale_secret_left {
        eprintln!(
            "Warning: a credential for the previous login may remain in the operating system credential store."
        );
    }
    if saved.replaced.durability == Durability::Uncertain {
        eprintln!("Warning: the saved login may not survive a system crash.");
    }
    Ok(ExitCode::SUCCESS)
}

/// No code was pasted before the attempt expired.
#[derive(Debug, thiserror::Error)]
#[error("the login expired; run the same `firma login` command again")]
struct PromptExpired;

async fn authenticate(args: Args) -> anyhow::Result<AuthenticatedLogin> {
    if cfg!(windows) && args.allow_plaintext_refresh_token {
        anyhow::bail!("plaintext refresh-token storage is supported only on Unix");
    }
    let mode = if args.development_loopback {
        OriginValidationMode::DevelopmentLoopback
    } else {
        OriginValidationMode::Production
    };
    let origin = ControlPlaneOrigin::new(args.control_plane_origin, mode)
        .context("invalid control plane origin")?;
    let client = NativeTokenClient::new(&origin).context("could not prepare token exchange")?;
    let scope = if cfg!(windows) {
        AuthorizationScope::AccessOnly
    } else {
        AuthorizationScope::OfflineAccess
    };
    let policy = if args.allow_plaintext_refresh_token {
        SecretPolicy::AllowPlaintextFile
    } else {
        SecretPolicy::NativeOnly
    };
    let dir = firma_connection_store::default_dir()?;
    tokio::task::spawn_blocking(move || {
        let store = ConnectionStore::open(dir)?;
        if store
            .shared()?
            .load()
            .context("could not inspect the saved login; run firma logout before logging in again")?
            .is_some()
        {
            anyhow::bail!("a login is already saved; run firma logout before logging in again");
        }
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("could not inspect the saved login")??;
    let exchange = authorize(&origin, args.terminal_code, scope).await?;
    let grant = client
        .exchange(exchange)
        .await
        .context("login exchange failed")?;
    let authenticated = client
        .prove(grant)
        .await
        .context("authenticated Workspace request failed")?;
    let saved = Connection {
        origin: origin.as_url().clone(),
        origin_mode: match mode {
            OriginValidationMode::Production => OriginMode::Production,
            OriginValidationMode::DevelopmentLoopback => OriginMode::DevelopmentLoopback,
        },
        workspace_id: authenticated.workspace_id,
        membership_id: authenticated.membership_id,
    };
    let refresh = authenticated
        .into_refresh_token()
        .map(ConnectionSecret::new);
    Ok(AuthenticatedLogin {
        connection: saved,
        refresh,
        policy,
    })
}

async fn authorize(
    origin: &ControlPlaneOrigin,
    terminal_code: bool,
    scope: AuthorizationScope,
) -> anyhow::Result<AuthorizedTokenExchange> {
    if terminal_code {
        authorize_terminal(origin, scope).await
    } else {
        authorize_loopback(origin, scope).await
    }
}

async fn authorize_terminal(
    origin: &ControlPlaneOrigin,
    scope: AuthorizationScope,
) -> anyhow::Result<AuthorizedTokenExchange> {
    if !io::stdin().is_terminal() || !io::stderr().is_terminal() {
        anyhow::bail!("terminal-code login requires an interactive terminal");
    }
    let attempt = AuthorizationAttempt::start().context("could not start authorization")?;
    let request = TerminalAuthorizationRequest::with_scope(origin, attempt, scope);
    print_and_open(request.as_url(), &mut io::stderr()).context("could not open login URL")?;
    let code = read_terminal_code().await?;
    request.complete(&code).context("invalid one-time code")
}

async fn authorize_loopback(
    origin: &ControlPlaneOrigin,
    scope: AuthorizationScope,
) -> anyhow::Result<AuthorizedTokenExchange> {
    let pending = AuthorizationAttempt::start()
        .context("could not start authorization")?
        .bind_loopback()
        .context("could not bind callback listener")?;
    let request = AuthorizationRequest::with_scope(origin, pending, scope);
    print_and_open(request.as_url(), &mut io::stderr()).context("could not open login URL")?;
    request
        .receive(
            CallbackWaitTimeout::try_from(CALLBACK_DEADLINE)
                .context("invalid callback deadline")?,
        )
        .await
        .context("login callback failed")
}

/// Publishes a login without replacing renewable authority implicitly.
///
/// The final check runs under the exclusive lock, so concurrent browser logins
/// cannot both observe an empty store. A newly issued credential that cannot be
/// published is allowed to expire on the server; no local recovery state is
/// created for it.
async fn save(login: AuthenticatedLogin) -> anyhow::Result<SavedLogin> {
    let AuthenticatedLogin {
        connection,
        refresh,
        policy,
    } = login;
    let dir = firma_connection_store::default_dir()?;
    tokio::task::spawn_blocking(move || {
        let store = ConnectionStore::open(dir)?;
        let guard = store.exclusive()?;
        let previous = guard.load().context(
            "could not inspect the saved login; run firma logout before logging in again",
        )?;
        if previous.is_some() {
            anyhow::bail!("a login is already saved; run firma logout before logging in again");
        }
        let replaced = guard.replace(&connection, refresh.as_ref(), policy)?;
        Ok(SavedLogin {
            dir: store.dir().to_path_buf(),
            replaced,
        })
    })
    .await
    .context("the save task failed")
    .and_then(std::convert::identity)
}

/// Reads the pasted code without echoing it, until the attempt expires.
/// Only the wait for the code is bounded: an exchange already under way is
/// never cut short.
async fn read_terminal_code() -> anyhow::Result<Zeroizing<String>> {
    let prompt = tokio::task::spawn_blocking(|| {
        dialoguer::Password::new()
            .with_prompt("Paste one-time login code")
            .interact()
            .map(Zeroizing::new)
    });
    let Ok(read) = tokio::time::timeout(CALLBACK_DEADLINE, prompt).await else {
        return Err(PromptExpired.into());
    };
    read.context("one-time code prompt failed")?
        .context("could not read one-time code")
}
