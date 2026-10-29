//! On-demand access to one saved renewable native login.

use std::time::Duration;

use firma_connection_store::{
    Backend, ConnectionSecret, ConnectionStore, SavedConnection, SecretPolicy, StoreError,
    WriteGuard,
};
use firma_identifiers::WorkspaceId;
use secrecy::SecretString;
use thiserror::Error;
// Tokio's clock, so a test can advance time past the renewal threshold.
use tokio::time::Instant;

use crate::protocol::{IdempotencyKey, is_retryable_status};
use crate::{
    ControlPlaneOrigin, ControlPlaneOriginError, LoginRefusal, NativeTokenClient, NativeTokenError,
};

const EARLY_REFRESH: Duration = Duration::from_mins(1);
const REFRESH_ATTEMPTS: usize = 3;
const RETRY_DELAY: Duration = Duration::from_millis(100);
const RECOVERY_WINDOW: Duration = Duration::from_secs(90);

/// An access token and the saved connection it was issued for, read under
/// the same lock that obtained it.
#[derive(Debug)]
pub struct SessionAccess {
    token: SecretString,
    origin: ControlPlaneOrigin,
    workspace_id: WorkspaceId,
}

impl SessionAccess {
    /// The bearer token; never log or format it.
    #[must_use]
    pub const fn token(&self) -> &SecretString {
        &self.token
    }

    /// The Control Plane that issued the token, the only one it may reach.
    #[must_use]
    pub const fn origin(&self) -> &ControlPlaneOrigin {
        &self.origin
    }

    /// The Workspace the token speaks for.
    #[must_use]
    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }
}

struct CachedAccess {
    access: SessionAccess,
    refresh_after: Instant,
}

struct PendingRefresh {
    guard: WriteGuard,
    saved: SavedConnection,
    origin: ControlPlaneOrigin,
    client: NativeTokenClient,
    key: IdempotencyKey,
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

    /// Drops the cached access token, so the next [`Self::access_token`]
    /// renews instead of returning a token the Control Plane refused.
    pub(crate) fn forget_access(&mut self) {
        self.cached = None;
    }

    /// Returns cached access or rotates and saves the renewable credential.
    ///
    /// # Errors
    /// Returns a redacted storage, origin, transport, or protocol error. If
    /// the process ends after the server consumes R0 but before R1 is saved,
    /// the caller must run `firma logout`, then `firma login`.
    pub async fn access_token(&mut self) -> Result<&SessionAccess, SessionError> {
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
                .map(|cached| &cached.access)
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
                    return Err(
                        if matches!(
                            source,
                            NativeTokenError::Refused(LoginRefusal::InvalidGrant)
                        ) {
                            SessionError::LoginExpired
                        } else {
                            SessionError::RenewalRefused { source }
                        },
                    );
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
        Ok(&self.cached.insert(access).access)
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
        return Err(SessionError::NotRenewable);
    }
    let policy = match saved.secret.backend() {
        Backend::File => SecretPolicy::AllowPlaintextFile,
        Backend::Native => SecretPolicy::NativeOnly,
        _ => return Err(SessionError::MissingCredential),
    };
    let origin = ControlPlaneOrigin::saved(&saved.connection)?;
    let client = NativeTokenClient::new(&origin)?;
    let key = IdempotencyKey::generate().map_err(NativeTokenError::from)?;
    Ok(PendingRefresh {
        guard,
        saved,
        origin,
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
        origin,
        policy,
        started_at,
        ..
    } = pending;
    let (access, successor, expires_in, workspace_id, membership_id) =
        grant
            .into_session_parts()
            .map_err(|source| SessionError::RenewalRefused { source })?;
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
        access: SessionAccess {
            token: access,
            origin,
            workspace_id,
        },
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
        NativeTokenError::Rejected(status) => is_retryable_status(*status),
        _ => false,
    }
}

/// Why a saved native login could not provide access.
#[derive(Debug, Error)]
pub enum SessionError {
    /// This process can no longer safely reuse the saved credential.
    #[error("the renewable login may have been consumed; run `firma logout`, then `firma login`")]
    LoginRequired,
    /// The Control Plane no longer renews the saved login: it expired, was
    /// revoked, or its Membership can no longer use it.
    #[error("the saved login expired or was revoked; run `firma logout`, then `firma login`")]
    LoginExpired,
    /// No login is saved locally.
    #[error("no login is saved; run `firma login`")]
    MissingConnection,
    /// The saved renewable credential could not be read.
    #[error("the saved login cannot be renewed; run `firma logout`, then `firma login`")]
    MissingCredential,
    /// The saved login is access-only: it has no renewable credential.
    #[error(
        "this saved login cannot be renewed; managed runs need a renewable login, so run `firma logout`, then `firma login` (not yet available on Windows)"
    )]
    NotRenewable,
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
    /// The Control Plane answered a refresh in a way no retry can change.
    #[error("the saved login could not be renewed; run `firma logout`, then `firma login`")]
    RenewalRefused {
        /// Redacted protocol failure.
        #[source]
        source: NativeTokenError,
    },
    /// A refresh request was sent but did not yield a usable successor.
    #[error(
        "the renewal outcome may be unknown; run `firma logout`, then `firma login` before retrying in a new process"
    )]
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
    #[error(
        "the renewed login names a different Workspace or Membership; run `firma logout`, then `firma login`"
    )]
    IdentityMismatch,
}
