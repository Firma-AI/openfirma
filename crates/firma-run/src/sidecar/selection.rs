//! Resolve `SidecarSelection` from the `--sidecar` CLI value and the
//! persisted/env sidecar endpoint.
//!
//! Precedence: CLI > persisted endpoint > default (local autostart).
//! Mirrors `crate::authority::selection`.

use std::str::FromStr;

use serde::Serialize;

use crate::config::SidecarEndpoint;
use crate::error::RunError;

/// CLI-side selection (value of `--sidecar`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum SidecarCli {
    /// Flag not passed.
    #[default]
    Unset,
    /// `--sidecar local`.
    Local,
    /// `--sidecar <tcp://...|unix:///...>`.
    Remote(String),
}

/// Final, resolved sidecar selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SidecarSelection {
    /// Autostart a per-run sidecar; the supervisor chooses the endpoint.
    Local,
    /// Use the external sidecar at this endpoint; never autostart.
    Remote(SidecarEndpoint),
}

/// Resolve the sidecar selection.
///
/// `persisted_endpoint` is the merged config-file / `FIRMA_SIDECAR_ENDPOINT`
/// value (the hard-coded fallback default is NOT included — `None` means
/// "nothing was explicitly configured").
///
/// # Errors
///
/// - [`RunError::SidecarLocalNoAutostart`] when `--sidecar local` is combined
///   with `--no-autostart`.
/// - [`RunError::MissingSidecar`] when nothing is configured and
///   `--no-autostart` forbids the local-autostart default.
/// - [`RunError::ConfigValidation`] when a `Remote` endpoint string fails to
///   parse as a [`SidecarEndpoint`].
pub fn resolve(
    cli: &SidecarCli,
    no_autostart: bool,
    persisted_endpoint: Option<&str>,
) -> Result<SidecarSelection, RunError> {
    match cli {
        SidecarCli::Local => {
            if no_autostart {
                return Err(RunError::SidecarLocalNoAutostart);
            }
            Ok(SidecarSelection::Local)
        }
        SidecarCli::Remote(raw) => Ok(SidecarSelection::Remote(parse_endpoint(raw)?)),
        SidecarCli::Unset => match persisted_endpoint {
            Some(raw) => Ok(SidecarSelection::Remote(parse_endpoint(raw)?)),
            None => {
                if no_autostart {
                    Err(RunError::MissingSidecar)
                } else {
                    Ok(SidecarSelection::Local)
                }
            }
        },
    }
}

fn parse_endpoint(raw: &str) -> Result<SidecarEndpoint, RunError> {
    SidecarEndpoint::from_str(raw).map_err(RunError::ConfigValidation)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn endpoint(s: &str) -> SidecarEndpoint {
        SidecarEndpoint::from_str(s).unwrap()
    }

    #[test]
    fn local_returns_local() {
        let sel = resolve(&SidecarCli::Local, false, None).unwrap();
        assert_eq!(sel, SidecarSelection::Local);
    }

    #[test]
    fn local_with_no_autostart_errors() {
        let err = resolve(&SidecarCli::Local, true, None).unwrap_err();
        assert!(matches!(err, RunError::SidecarLocalNoAutostart));
    }

    #[test]
    fn remote_tcp_parses() {
        let sel = resolve(
            &SidecarCli::Remote("tcp://127.0.0.1:9000".into()),
            false,
            None,
        )
        .unwrap();
        assert_eq!(
            sel,
            SidecarSelection::Remote(endpoint("tcp://127.0.0.1:9000"))
        );
    }

    #[test]
    fn remote_unix_parses() {
        let sel = resolve(
            &SidecarCli::Remote("unix:///tmp/s.sock".into()),
            false,
            None,
        )
        .unwrap();
        assert_eq!(
            sel,
            SidecarSelection::Remote(endpoint("unix:///tmp/s.sock"))
        );
    }

    #[test]
    fn remote_invalid_errors() {
        let err = resolve(&SidecarCli::Remote("http://nope".into()), false, None).unwrap_err();
        assert!(matches!(err, RunError::ConfigValidation(_)));
    }

    #[test]
    fn unset_with_persisted_is_remote() {
        let sel = resolve(&SidecarCli::Unset, false, Some("tcp://10.0.0.1:8080")).unwrap();
        assert_eq!(
            sel,
            SidecarSelection::Remote(endpoint("tcp://10.0.0.1:8080"))
        );
    }

    #[test]
    fn unset_without_persisted_defaults_to_local() {
        let sel = resolve(&SidecarCli::Unset, false, None).unwrap();
        assert_eq!(sel, SidecarSelection::Local);
    }

    #[test]
    fn unset_without_persisted_and_no_autostart_errors() {
        let err = resolve(&SidecarCli::Unset, true, None).unwrap_err();
        assert!(matches!(err, RunError::MissingSidecar));
    }

    #[test]
    fn remote_wins_even_with_no_autostart() {
        let sel = resolve(
            &SidecarCli::Remote("tcp://127.0.0.1:9000".into()),
            true,
            None,
        )
        .unwrap();
        assert_eq!(
            sel,
            SidecarSelection::Remote(endpoint("tcp://127.0.0.1:9000"))
        );
    }
}
