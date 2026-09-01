pub mod approval_wait;
pub mod guard;
pub mod issue;
pub mod refresh;

use std::path::Path;

use crate::config::CapabilitySource;
use crate::error::RunError;

/// Decodes the wire `CapabilityToken.signature` field into the raw PASETO
/// token string.
///
/// The `signature` bytes carry the PASETO token as UTF-8 — the one wire
/// convention shared by `IssueCapability` and `GetApprovalOutcome`. Both
/// decoders call this so the convention is interpreted in exactly one
/// place.
fn paseto_from_wire_token(
    token: firma_protobuf::v1::CapabilityToken,
) -> Result<String, std::string::FromUtf8Error> {
    String::from_utf8(token.signature)
}

/// Decodes a wire timestamp into a UTC instant, rejecting malformed values.
///
/// Negative nanos (or an unrepresentable instant) yield `None` instead of
/// being reinterpreted as a different point in time — the one invariant
/// shared by every timestamp this module reads off the wire.
fn datetime_from_wire_timestamp(
    timestamp: prost_types::Timestamp,
) -> Option<chrono::DateTime<chrono::Utc>> {
    u32::try_from(timestamp.nanos)
        .ok()
        .and_then(|nanos| chrono::DateTime::from_timestamp(timestamp.seconds, nanos))
}

/// Read the operator-supplied capability token for a `firma run` session.
///
/// Only [`CapabilitySource::File`] carries a bring-your-own token; the token is
/// injected into the agent process environment once at launch (see
/// `build_execution_env`). Rotation is delegated to the agent via the
/// `FIRMA_CAPABILITY_FILE` env var, so this is a one-shot read with no
/// background refresh — the firma-minted per-session path uses
/// [`refresh::CapabilityRefresher`] instead.
///
/// # Errors
///
/// Returns [`RunError::Capability`] when the file is unreadable or empty.
pub fn read_capability_token(source: &CapabilitySource) -> Result<Option<String>, RunError> {
    match source {
        CapabilitySource::Disabled => Ok(None),
        CapabilitySource::File { path } => read_token(path).map(Some),
    }
}

fn read_token(path: &Path) -> Result<String, RunError> {
    let value = std::fs::read_to_string(path)
        .map_err(|error| RunError::Capability(format!("{}: {error}", path.display())))?;

    let token = value.trim().to_string();
    if token.is_empty() {
        return Err(RunError::Capability(format!(
            "capability file {} is empty",
            path.display()
        )));
    }

    Ok(token)
}
