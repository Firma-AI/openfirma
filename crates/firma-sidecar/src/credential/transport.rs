// Read-only transport view combining an enforcement-approved envelope
// with its injected credentials, ready for the connector layer to forward.

use firma_core::ExecutionEnvelope;

use super::InjectedCredentials;

/// Immutable bundle of an [`ExecutionEnvelope`] and its
/// [`InjectedCredentials`], produced after enforcement passes and
/// credential injection completes.
///
/// Handed to the connector layer as the single unit it needs to build
/// the outbound request. Neither the envelope nor the credentials can
/// be mutated through this view.
#[derive(Debug, Clone)]
pub struct TransportView {
    envelope: ExecutionEnvelope,
    credentials: InjectedCredentials,
}

#[expect(
    dead_code,
    reason = "consumed by connector/interceptor callers once wired"
)]
impl TransportView {
    /// Creates a new [`TransportView`] from an execution envelope and injected credentials.
    #[must_use]
    pub fn new(envelope: ExecutionEnvelope, credentials: InjectedCredentials) -> Self {
        Self {
            envelope,
            credentials,
        }
    }

    /// Returns a reference to the [`ExecutionEnvelope`].
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
mod tests {
    use super::*;
    use firma_core::{ActionParams, ExecutionIntent, ExecutionMetadata, HttpMethod, HttpParams};
    use std::collections::HashMap;

    fn sample_envelope() -> ExecutionEnvelope {
        ExecutionEnvelope::new(
            ExecutionIntent {
                action_class: "http.get".to_string(),
                resource: "https://api.example.com".to_string(),
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
                session_id: "sess_001".to_string(),
                agent_id: "agent_abc".to_string(),
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

        assert_eq!(view.envelope().intent().action_class, "http.get");
        assert_eq!(
            view.credentials().get("Authorization").map(String::as_str),
            Some("Bearer secret")
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
            view.envelope().metadata().agent_id
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
