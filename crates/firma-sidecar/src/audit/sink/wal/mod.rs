//! Durable audit retry queue. Delivery never precedes the journal sync.
//!
//! Only a matching committed receipt reclaims a delivered record. Rejections are
//! retained in a separate synced archive before removing them from the queue, so
//! an invalid event cannot prevent delivery of the next run's events.

mod journal;

use std::path::PathBuf;
use std::time::Duration;

use firma_config_utils::NonZeroDuration;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::submission::{Submission, SubmissionClient};
use crate::audit::{AuditSink, AuditSinkError, ExecutionEvent};
use crate::authority_credentials::ResolvedSidecarCredentials;
use journal::{Journal, Scope};

const REPLAY_LIMIT: usize = 32;
const RETRY_INTERVAL: Duration = Duration::from_secs(1);

/// A bounded, destination-bound WAL. Capacity never evicts pending records.
#[derive(Debug)]
pub struct WalAuditSink {
    endpoint: String,
    wal_path: PathBuf,
    wal_max_bytes: u64,
    request_timeout: NonZeroDuration,
    credentials: Option<ResolvedSidecarCredentials>,
}

impl WalAuditSink {
    pub(crate) fn new(
        endpoint: impl Into<String>,
        wal_path: impl Into<PathBuf>,
        wal_max_bytes: u64,
        request_timeout: NonZeroDuration,
        credentials: Option<ResolvedSidecarCredentials>,
    ) -> Self {
        Self {
            endpoint: endpoint.into(),
            wal_path: wal_path.into(),
            wal_max_bytes,
            request_timeout,
            credentials,
        }
    }
}

impl AuditSink for WalAuditSink {
    async fn run(
        self,
        mut rx: mpsc::Receiver<ExecutionEvent>,
        exit: CancellationToken,
    ) -> Result<(), AuditSinkError> {
        let scope = Scope::new(&self.endpoint, self.credentials.as_ref());
        let mut journal = Journal::open(self.wal_path, self.wal_max_bytes, scope).await?;
        let mut client =
            SubmissionClient::new(self.endpoint, self.credentials, self.request_timeout);
        let mut retry = tokio::time::interval(RETRY_INTERVAL);
        retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                () = exit.cancelled() => {
                    // The signing adapter shares this token and drops its sender
                    // after draining. Retain its already buffered events.
                    while let Some(event) = rx.recv().await {
                        journal = journal.append(event).await?;
                    }
                    return Ok(());
                }
                event = rx.recv() => {
                    let Some(event) = event else {
                        replay(journal, &mut client, &exit).await?;
                        return Ok(());
                    };
                    journal = journal.append(event).await?;
                }
                _ = retry.tick() => {
                    journal = replay(journal, &mut client, &exit).await?;
                }
            }
        }
    }
}

async fn replay(
    journal: Journal,
    client: &mut SubmissionClient,
    exit: &CancellationToken,
) -> Result<Journal, AuditSinkError> {
    let mut consumed = 0;
    for record in journal.records().take(REPLAY_LIMIT) {
        if exit.is_cancelled() {
            break;
        }
        let Ok(event) = serde_json::from_slice::<ExecutionEvent>(record) else {
            journal
                .reject(
                    record.clone(),
                    "malformed_record",
                    "invalid audit JSON record",
                )
                .await?;
            tracing::warn!("malformed audit record retained in rejection archive");
            consumed += 1;
            continue;
        };
        match client.submit(event).await {
            Submission::Persisted => consumed += 1,
            Submission::Rejected(status) => {
                journal
                    .reject(record.clone(), "invalid_argument", status.message())
                    .await?;
                tracing::warn!(code = %status.code(), "audit event retained in rejection archive");
                consumed += 1;
            }
            Submission::Retry(status) => {
                tracing::warn!(code = %status.code(), "audit delivery unacknowledged; WAL retained");
                break;
            }
        }
    }
    journal.reclaim(consumed).await
}
