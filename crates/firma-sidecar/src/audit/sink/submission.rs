//! Evidence-aware delivery. A response is useful only after the collector commits.

use firma_config_utils::NonZeroDuration;
use firma_protobuf::v1::audit_service_client::AuditServiceClient;
use tonic::transport::{Channel, Endpoint};
use tonic::{Code, Status};

use super::{execution_event_to_proto, metadata::stream_events_request};
use crate::audit::{AuditSinkError, ExecutionEvent};
use crate::authority_client::rejects_run;
use crate::authority_credentials::SidecarCredential;

pub(super) enum Submission {
    Persisted,
    Rejected(Status),
    Retry(Status),
    /// The Authority no longer accepts this Sidecar's run.
    RunRejected(Status),
}

pub(super) struct SubmissionClient {
    /// The audit service, over TLS for an `https` URL.
    dial: Endpoint,
    credentials: Option<SidecarCredential>,
    /// Bounds the connect, the request, and the whole submission.
    request_timeout: NonZeroDuration,
    client: Option<AuditServiceClient<Channel>>,
}

impl SubmissionClient {
    pub(super) fn new(
        dial: Endpoint,
        credentials: Option<SidecarCredential>,
        request_timeout: NonZeroDuration,
    ) -> Self {
        Self {
            dial,
            credentials,
            request_timeout,
            client: None,
        }
    }

    async fn connect(&mut self) -> Result<(), AuditSinkError> {
        let channel = self
            .dial
            .clone()
            .connect_timeout(self.request_timeout.duration())
            .timeout(self.request_timeout.duration())
            .connect()
            .await
            .map_err(|error| AuditSinkError::BindFailed(error.to_string()))?;
        self.client = Some(AuditServiceClient::new(channel));
        Ok(())
    }

    /// Sends exactly one immutable event; never falls back to an older RPC.
    pub(super) async fn submit(&mut self, event: ExecutionEvent) -> Submission {
        tokio::time::timeout(self.request_timeout.duration(), self.send(event))
            .await
            .unwrap_or_else(|_| {
                Submission::Retry(Status::deadline_exceeded("audit acknowledgement timed out"))
            })
    }

    async fn send(&mut self, event: ExecutionEvent) -> Submission {
        if self.client.is_none()
            && let Err(error) = self.connect().await
        {
            return Submission::Retry(Status::unavailable(error.to_string()));
        }
        let source_id = event.event_id.clone();
        let Ok(request) =
            stream_events_request(execution_event_to_proto(event), self.credentials.as_ref())
        else {
            return Submission::Retry(Status::unauthenticated("invalid audit credentials"));
        };
        let Some(client) = self.client.as_mut() else {
            return Submission::Retry(Status::unavailable("audit client unavailable"));
        };
        match client.submit_event(request).await {
            Ok(response) => {
                let receipt = response.into_inner();
                if receipt.durably_persisted
                    && receipt.events_received == 1
                    && receipt.last_event_id == source_id
                {
                    Submission::Persisted
                } else {
                    Submission::Retry(Status::data_loss(
                        "invalid audit persistence acknowledgement",
                    ))
                }
            }
            Err(status) if status.code() == Code::InvalidArgument => Submission::Rejected(status),
            Err(status) if rejects_run(&status, self.credentials.as_ref()) => {
                Submission::RunRejected(status)
            }
            Err(status) => {
                self.client = None;
                Submission::Retry(status)
            }
        }
    }
}
