//! Read-only transport view consumed by connector implementations.
//!
//! The sidecar assembles a [`TransportView`] after enforcement passes
//! and credential injection completes. The view pairs an approved
//! [`ExecutionEnvelope`] with its [`InjectedCredentials`] and is the
//! single value handed to the [`Connector`] layer at dispatch time.
//!
//! Neither the envelope nor the credentials can be mutated through
//! this view. This is intentional: by the time a connector runs, Stage
//! 1, Stage 2, and credential injection have all executed, and the
//! connector's role is limited to protocol translation and dispatch
//! (FEP §6.2).
//!
//! [`Connector`]: crate::connector::Connector

use crate::ExecutionEnvelope;
use crate::credential::InjectedCredentials;

/// Immutable pairing of an [`ExecutionEnvelope`] and its
/// [`InjectedCredentials`], handed to the connector layer as the
/// single input it needs to build the outbound request.
///
/// Neither field can be mutated through this view. Connectors read the
/// envelope to derive the request (URL, method, headers, body) and
/// read the credentials to merge injected headers before dispatch.
///
/// # Examples
///
/// ```
/// use std::collections::HashMap;
/// use firma_core::{InjectedCredentials, TransportView};
/// # use firma_core::{ActionParams, ExecutionEnvelope, ExecutionIntent,
/// #     ExecutionMetadata, HttpMethod, HttpParams};
/// # fn envelope() -> ExecutionEnvelope {
/// #     ExecutionEnvelope::new(
/// #         ExecutionIntent {
/// #             action_class: "filesystem.read".to_string(),
/// #             resource: ExecutionIntent::resource_map_from("https://api.example.com"),
/// #             params: ActionParams::Http(HttpParams {
/// #                 method: HttpMethod::GET,
/// #                 headers: HashMap::new(),
/// #                 body: None,
/// #                 query: HashMap::new(),
/// #             }),
/// #             raw_transport: "https".to_string(),
/// #             raw_action_ref: "GET /".to_string(),
/// #         },
/// #         "v4.public.eyJ0...".to_string(),
/// #         ExecutionMetadata {
/// #             session_id: "sess_001".parse().unwrap(),
/// #             agent_id: "agent_abc".parse().unwrap(),
/// #             timestamp: chrono::Utc::now(),
/// #             trace_id: None,
/// #             budget_consumed: 0.0,
/// #             risk_score: None,
/// #         },
/// #         None,
/// #     )
/// # }
///
/// let view = TransportView::new(envelope(), InjectedCredentials::empty());
/// assert!(view.credentials().is_empty());
/// ```
#[derive(Debug, Clone)]
pub struct TransportView {
    envelope: ExecutionEnvelope,
    credentials: InjectedCredentials,
}

impl TransportView {
    /// Creates a new [`TransportView`] from an envelope and its
    /// injected credentials.
    #[must_use]
    pub fn new(envelope: ExecutionEnvelope, credentials: InjectedCredentials) -> Self {
        Self {
            envelope,
            credentials,
        }
    }

    /// Returns a reference to the enforced [`ExecutionEnvelope`].
    #[must_use]
    pub fn envelope(&self) -> &ExecutionEnvelope {
        &self.envelope
    }

    /// Returns a reference to the [`InjectedCredentials`].
    #[must_use]
    pub fn credentials(&self) -> &InjectedCredentials {
        &self.credentials
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::{ActionParams, ExecutionIntent, ExecutionMetadata, HttpMethod, HttpParams};
    use std::collections::HashMap;

    fn sample_envelope() -> ExecutionEnvelope {
        ExecutionEnvelope::new(
            ExecutionIntent {
                action_class: "filesystem.read".to_string(),
                resource: crate::ExecutionIntent::resource_map_from("https://api.example.com"),
                params: ActionParams::Http(HttpParams {
                    method: HttpMethod::GET,
                    headers: HashMap::new(),
                    body: None,
                    query: HashMap::new(),
                }),
                raw_transport: "https".to_string(),
                raw_action_ref: "GET /".to_string(),
            },
            "v4.public.eyJ0...".to_string(),
            ExecutionMetadata {
                session_id: "sess_001".parse().expect("literal session id"),
                agent_id: "agent_abc".parse().expect("literal agent id"),
                timestamp: chrono::Utc::now(),
                trace_id: None,
                budget_consumed: 0.0,
                risk_score: None,
            },
            None,
        )
    }

    #[test]
    fn test_transport_view_construction() {
        let creds = InjectedCredentials::new(HashMap::from([(
            "Authorization".to_string(),
            "Bearer secret".to_string(),
        )]));
        let view = TransportView::new(sample_envelope(), creds);

        assert_eq!(view.envelope().intent().action_class, "filesystem.read");
        assert_eq!(
            view.credentials().get("Authorization").map(String::as_str),
            Some("Bearer secret"),
        );
    }

    #[test]
    fn test_transport_view_empty_credentials() {
        let view = TransportView::new(sample_envelope(), InjectedCredentials::empty());
        assert!(view.credentials().is_empty());
    }

    #[test]
    fn test_transport_view_clone() {
        let creds = InjectedCredentials::new(HashMap::from([(
            "X-Api-Key".to_string(),
            "key123".to_string(),
        )]));
        let view = TransportView::new(sample_envelope(), creds);
        let cloned = view.clone();

        assert_eq!(
            cloned.envelope().metadata().agent_id,
            view.envelope().metadata().agent_id,
        );
        assert_eq!(cloned.credentials().headers(), view.credentials().headers());
    }

    #[test]
    fn test_transport_view_debug() {
        let view = TransportView::new(sample_envelope(), InjectedCredentials::empty());
        let debug = format!("{view:?}");
        assert!(debug.contains("TransportView"));
    }
}
