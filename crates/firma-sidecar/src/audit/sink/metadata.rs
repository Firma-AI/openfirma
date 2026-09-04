//! Sidecar credential metadata for outbound audit streams.

use firma_protobuf::v1::SidecarCredentials;
use tonic::Request;
use tonic::metadata::{MetadataMap, MetadataValue};

use crate::audit::AuditSinkError;
use crate::authority_credentials::ResolvedSidecarCredentials;

// These keys authenticate the audit stream envelope.
// we uses them to look up the registered Sidecar and derive scope
// from that record, rather than trusting workspace or agent IDs in the body.
const SIDECAR_WORKSPACE_ID_METADATA: &str = "firma-workspace-id";
const SIDECAR_ID_METADATA: &str = "firma-sidecar-id";
const SIDECAR_PSK_METADATA: &str = "firma-sidecar-psk";

/// Builds an audit stream request with optional sidecar credentials.
pub(super) fn stream_events_request<T>(
    stream: T,
    credentials: Option<&ResolvedSidecarCredentials>,
) -> Result<Request<T>, AuditSinkError> {
    let mut request = Request::new(stream);
    if let Some(credentials) = credentials {
        attach_sidecar_credentials(request.metadata_mut(), &credentials.to_proto())?;
    }

    Ok(request)
}

fn attach_sidecar_credentials(
    metadata: &mut MetadataMap,
    credentials: &SidecarCredentials,
) -> Result<(), AuditSinkError> {
    insert_metadata(
        metadata,
        SIDECAR_WORKSPACE_ID_METADATA,
        credentials.workspace_id.as_str(),
    )?;

    insert_metadata(
        metadata,
        SIDECAR_ID_METADATA,
        credentials.sidecar_id.as_str(),
    )?;

    insert_metadata(
        metadata,
        SIDECAR_PSK_METADATA,
        credentials.pre_shared_key.as_str(),
    )
}

fn insert_metadata(
    metadata: &mut MetadataMap,
    key: &'static str,
    value: &str,
) -> Result<(), AuditSinkError> {
    let value = MetadataValue::try_from(value).map_err(|_error| {
        AuditSinkError::BindFailed(format!("sidecar audit metadata `{key}` is not valid ASCII"))
    })?;

    metadata.insert(key, value);

    Ok(())
}
