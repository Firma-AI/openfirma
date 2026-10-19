//! On-demand access to one saved renewable native login.

use std::time::{Duration, Instant};

use firma_connection_store::{
    Backend, ConnectionSecret, ConnectionStore, OriginMode, SavedConnection, SecretPolicy,
    StoreError, WriteGuard,
};
use secrecy::SecretString;
use thiserror::Error;

use crate::protocol::RefreshIdempotencyKey;
use crate::{
    ControlPlaneOrigin, ControlPlaneOriginError, LoginRefusal, NativeTokenClient, NativeTokenError,
    OriginValidationMode,
};

const EARLY_REFRESH: Duration = Duration::from_mins(1);
const REFRESH_ATTEMPTS: usize = 3;
const RETRY_DELAY: Duration = Duration::from_millis(100);
const RECOVERY_WINDOW: Duration = Duration::from_secs(90);

struct CachedAccess {
    secret: SecretString,
    refresh_after: Instant,
}

struct PendingRefresh {
    guard: WriteGuard,
    saved: SavedConnection,
    client: NativeTokenClient,
    key: RefreshIdempotencyKey,
    policy: SecretPolicy,
    started_at: Instant,
    outcome_unknown: bool,
}

/// Supplies short-lived access from a saved renewable login.
///
/// The access token and refresh UUID exist only in this process. The store's
/// exclusive lock covers loading R0, every bounded retry, and replacing it
/// with R1, so another process waits and then reads the successor.
pub struct NativeSession {
    store: ConnectionStore,
    cached: Option<CachedAccess>,
    pending: Option<PendingRefresh>,
    login_required: bool,
}

impl NativeSession {
    /// Uses `store` as the single source of the renewable credential.
    #[must_use]
    pub const fn new(store: ConnectionStore) -> Self {
        Self {
            store,
            cached: None,
            pending: None,
            login_required: false,
        }
    }

    /// Returns cached access or rotates and saves the renewable credential.
    ///
    /// # Errors
    /// Returns a redacted storage, origin, transport, or protocol error. If
    /// the process ends after the server consumes R0 but before R1 is saved,
    /// the caller must run `firma login` again.
    pub async fn access_token(&mut self) -> Result<&SecretString, SessionError> {
        if self.login_required {
            return Err(SessionError::LoginRequired);
        }
        let use_cached = self
            .cached
            .as_ref()
            .is_some_and(|cached| Instant::now() < cached.refresh_after);
        if use_cached {
            return self
                .cached
                .as_ref()
                .map(|cached| &cached.secret)
                .ok_or(SessionError::MissingCredential);
        }
        if self.pending.as_ref().is_some_and(|pending| {
            pending.outcome_unknown && pending.started_at.elapsed() >= RECOVERY_WINDOW
        }) {
            self.pending = None;
            self.login_required = true;
            return Err(SessionError::LoginRequired);
        }
        if self.pending.is_none() {
            self.pending = Some(prepare_refresh(self.store.clone()).await?);
        }
        let pending = self
            .pending
            .as_mut()
            .ok_or(SessionError::MissingCredential)?;
        let grant = match refresh_with_retry(pending).await {
            Ok(grant) => grant,
            Err(source) => {
                if !is_retryable(&source) {
                    self.pending = None;
                    self.login_required = true;
                } else if !pending.outcome_unknown {
                    // A connection failure before dispatch leaves R0 untouched.
                    self.pending = None;
                }
                return Err(SessionError::RefreshFailed { source });
            }
        };
        let pending = self.pending.take().ok_or(SessionError::MissingCredential)?;
        // A cancelled blocking save may still publish R1. Do not start a new
        // refresh while its outcome is unknown.
        self.login_required = true;
        let access = complete_refresh(pending, grant).await?;
        self.login_required = false;
        Ok(&self.cached.insert(access).secret)
    }
}

async fn prepare_refresh(store: ConnectionStore) -> Result<PendingRefresh, SessionError> {
    let (guard, saved) = tokio::task::spawn_blocking(move || {
        let guard = store.exclusive()?;
        let saved = guard.load()?.ok_or(SessionError::MissingConnection)?;
        Ok::<_, SessionError>((guard, saved))
    })
    .await??;
    if saved.secret.secret().is_none() {
        return Err(SessionError::MissingCredential);
    }
    let policy = match saved.secret.backend() {
        Backend::File => SecretPolicy::AllowPlaintextFile,
        Backend::Native => SecretPolicy::NativeOnly,
        _ => return Err(SessionError::MissingCredential),
    };
    let mode = match saved.connection.origin_mode {
        OriginMode::Production => OriginValidationMode::Production,
        OriginMode::DevelopmentLoopback => OriginValidationMode::DevelopmentLoopback,
    };
    let origin = ControlPlaneOrigin::new(saved.connection.origin.clone(), mode)?;
    let client = NativeTokenClient::new(&origin)?;
    let key = RefreshIdempotencyKey::generate()?;
    Ok(PendingRefresh {
        guard,
        saved,
        client,
        key,
        policy,
        started_at: Instant::now(),
        outcome_unknown: false,
    })
}

async fn complete_refresh(
    pending: PendingRefresh,
    grant: crate::NativeAccessGrant,
) -> Result<CachedAccess, SessionError> {
    let PendingRefresh {
        guard,
        saved,
        policy,
        started_at,
        ..
    } = pending;
    let (access, successor, expires_in, workspace_id, membership_id) =
        grant
            .into_session_parts()
            .map_err(|source| SessionError::RefreshFailed { source })?;
    if workspace_id != saved.connection.workspace_id
        || membership_id != saved.connection.membership_id
    {
        return Err(SessionError::IdentityMismatch);
    }
    let successor = ConnectionSecret::new(successor);
    tokio::task::spawn_blocking(move || {
        guard.replace(&saved.connection, Some(&successor), policy)?;
        Ok::<_, StoreError>(())
    })
    .await?
    .map_err(|source| SessionError::SaveAfterRefresh { source })?;
    Ok(CachedAccess {
        secret: access,
        refresh_after: started_at + expires_in.saturating_sub(EARLY_REFRESH),
    })
}

async fn refresh_with_retry(
    pending: &mut PendingRefresh,
) -> Result<crate::NativeAccessGrant, NativeTokenError> {
    for attempt in 1..=REFRESH_ATTEMPTS {
        let previously_unknown = pending.outcome_unknown;
        // Retain R0, the key and lock in the session even when this future is
        // cancelled while awaiting the response.
        pending.outcome_unknown = true;
        let credential = pending
            .saved
            .secret
            .secret()
            .ok_or(NativeTokenError::InvalidResponse)?;
        let result = pending
            .client
            .refresh(credential.as_secret(), pending.key)
            .await;
        if matches!(&result, Err(NativeTokenError::Transport(error)) if error.is_connect()) {
            pending.outcome_unknown = previously_unknown;
        }
        match result {
            Ok(grant) => return Ok(grant),
            Err(error) if attempt < REFRESH_ATTEMPTS && is_retryable(&error) => {
                tokio::time::sleep(RETRY_DELAY).await;
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("refresh attempts are nonzero")
}

fn is_retryable(error: &NativeTokenError) -> bool {
    match error {
        NativeTokenError::Transport(_)
        | NativeTokenError::Refused(
            LoginRefusal::TemporarilyUnavailable | LoginRefusal::ServerError,
        ) => true,
        NativeTokenError::Rejected(status) => {
            *status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
        }
        _ => false,
    }
}

/// Why a saved native login could not provide access.
#[derive(Debug, Error)]
pub enum SessionError {
    /// This process can no longer safely reuse the saved credential.
    #[error("the renewable login may have been consumed; run `firma logout`, then `firma login`")]
    LoginRequired,
    /// No login is saved locally.
    #[error("no login is saved; run `firma login`")]
    MissingConnection,
    /// The saved login has no renewable credential.
    #[error("the saved login cannot be renewed; run `firma login`")]
    MissingCredential,
    /// A blocking store operation could not complete.
    #[error("native login storage task failed")]
    BlockingTask(#[from] tokio::task::JoinError),
    /// The saved connection could not be read or replaced.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The saved Control Plane origin is no longer valid.
    #[error(transparent)]
    Origin(#[from] ControlPlaneOriginError),
    /// Token-client setup failed before a refresh request was sent.
    #[error(transparent)]
    TokenSetup(#[from] NativeTokenError),
    /// A refresh request was sent but did not yield a usable successor.
    #[error("native refresh failed")]
    RefreshFailed {
        /// Redacted protocol or transport failure.
        #[source]
        source: NativeTokenError,
    },
    /// The successor was issued but could not replace the saved credential.
    #[error("the refreshed credential could not be saved; run `firma logout`, then `firma login`")]
    SaveAfterRefresh {
        /// Local storage failure.
        #[source]
        source: StoreError,
    },
    /// The refresh response named a different saved identity.
    #[error("native refresh returned a different Workspace or Membership")]
    IdentityMismatch,
}
