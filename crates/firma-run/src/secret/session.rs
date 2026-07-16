//! Broker-side application of a secret-mediation decision to a launch.
//!
//! This is the orchestration seam that ties the pieces together: the broker has
//! already asked the Sidecar for a [`pep::SecretPepOutcome`] and captured the
//! tool's stdout; this applies the outcome and writes the (possibly rewritten)
//! result to the agent. It is fail-closed — on a deny or a transform error the
//! plaintext output is **never** written to the agent.
//!
//! The surrounding process wiring — the shim that execs the real vault CLI, the
//! `SCM_RIGHTS` fd handshake, and the accept loop — lives in [`broker`] and the
//! shim binary; this function is deliberately I/O-generic so it can be tested
//! over in-memory streams.
//!
//! See `docs/architecture/secrets-interception.md`.

use std::io::{self, Read, Write};

use arc_swap::ArcSwap;
use firma_core::SecretMediation;

use super::SecretStore;
use super::intercept::{InterceptError, intercept};
use super::pep::SecretPepOutcome;

/// Errors from applying a decision to a wrapped launch.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// The launch was denied (fail closed); nothing was written to the agent.
    #[error("launch denied by policy: {0}")]
    Denied(String),
    /// Intercept extraction/rewrite failed; nothing was written to the agent.
    #[error(transparent)]
    Intercept(#[from] InterceptError),
    /// Copying between the tool and the agent failed.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// A redact decision reached the intercept path (redact wraps a target
    /// tool's bidirectional streams, not a vault CLI's one-shot output).
    #[error("redact decision is not valid on the intercept path")]
    UnexpectedRedact,
}

/// Apply a secret-mediation `outcome` to a wrapped launch's captured output.
///
/// Writes the result the agent should see to `agent_output`:
///
/// - [`SecretPepOutcome::Mediate`] with an `Intercept` directive: extract the
///   secrets into `store` and write the placeholder-substituted output.
/// - [`SecretPepOutcome::Passthrough`]: copy the output through unchanged.
/// - [`SecretPepOutcome::Deny`]: write nothing and fail closed.
///
/// # Errors
///
/// Returns [`SessionError`] on deny, an intercept failure, an I/O error, or a
/// misrouted redact decision. In every error case, no plaintext is written to
/// `agent_output`.
pub fn run_intercept<R: Read, W: Write>(
    outcome: &SecretPepOutcome,
    tool_output: &mut R,
    agent_output: &mut W,
    store: &ArcSwap<SecretStore>,
) -> Result<(), SessionError> {
    match outcome {
        SecretPepOutcome::Deny(reason) => Err(SessionError::Denied(reason.clone())),
        SecretPepOutcome::Passthrough => {
            io::copy(tool_output, agent_output)?;
            Ok(())
        }
        SecretPepOutcome::Mediate(SecretMediation::Intercept {
            matcher,
            placeholder,
        }) => {
            // Read the whole output before rewriting: the matcher parses the
            // full document (JSON) or scans the full text (regex).
            let mut raw = Vec::new();
            tool_output.read_to_end(&mut raw)?;
            // On failure this returns before writing, so the raw plaintext in
            // `raw` never reaches the agent.
            let rewritten = intercept(matcher, &raw, placeholder, store)?;
            agent_output.write_all(&rewritten)?;
            Ok(())
        }
        SecretPepOutcome::Mediate(SecretMediation::Redact { .. }) => {
            Err(SessionError::UnexpectedRedact)
        }
    }
}

#[cfg(test)]
mod tests {
    use firma_core::{SecretMatcher, SecretTransform};

    use super::*;

    fn intercept_outcome() -> SecretPepOutcome {
        SecretPepOutcome::Mediate(SecretMediation::Intercept {
            matcher: SecretMatcher::Json {
                value_path: "$[*].value".to_string(),
                name_path: "$[*].key".to_string(),
            },
            placeholder: "firma-secret://bitwarden/{name}".to_string(),
        })
    }

    #[test]
    fn intercept_rewrites_output_and_populates_store() {
        let store = ArcSwap::from_pointee(SecretStore::new());
        let mut tool = &br#"[{"key":"db","value":"s3cr3t"}]"#[..];
        let mut agent = Vec::new();

        run_intercept(&intercept_outcome(), &mut tool, &mut agent, &store).unwrap();

        let seen: serde_json::Value = serde_json::from_slice(&agent).unwrap();
        assert_eq!(
            seen[0]["value"],
            serde_json::json!("firma-secret://bitwarden/db")
        );
        assert_eq!(
            store.load().resolve("firma-secret://bitwarden/db"),
            Some(&b"s3cr3t"[..])
        );
    }

    #[test]
    fn passthrough_copies_output_unchanged() {
        let store = ArcSwap::from_pointee(SecretStore::new());
        let mut tool = &b"plain output"[..];
        let mut agent = Vec::new();

        run_intercept(
            &SecretPepOutcome::Passthrough,
            &mut tool,
            &mut agent,
            &store,
        )
        .unwrap();
        assert_eq!(agent, b"plain output");
        assert!(store.load().is_empty());
    }

    #[test]
    fn deny_writes_nothing_and_fails_closed() {
        let store = ArcSwap::from_pointee(SecretStore::new());
        let mut tool = &b"secret output"[..];
        let mut agent = Vec::new();

        let error = run_intercept(
            &SecretPepOutcome::Deny("blocked".to_string()),
            &mut tool,
            &mut agent,
            &store,
        )
        .unwrap_err();
        assert!(matches!(error, SessionError::Denied(_)));
        assert!(
            agent.is_empty(),
            "no plaintext must reach the agent on deny"
        );
    }

    #[test]
    fn intercept_failure_writes_nothing() {
        let store = ArcSwap::from_pointee(SecretStore::new());
        let mut tool = &b"not json"[..];
        let mut agent = Vec::new();

        let error = run_intercept(&intercept_outcome(), &mut tool, &mut agent, &store).unwrap_err();
        assert!(matches!(error, SessionError::Intercept(_)));
        assert!(
            agent.is_empty(),
            "no plaintext must reach the agent when intercept fails"
        );
    }

    #[test]
    fn redact_decision_is_rejected_on_intercept_path() {
        let store = ArcSwap::from_pointee(SecretStore::new());
        let mut tool = &b""[..];
        let mut agent = Vec::new();
        let outcome = SecretPepOutcome::Mediate(SecretMediation::Redact {
            transform: SecretTransform::Raw,
        });

        let error = run_intercept(&outcome, &mut tool, &mut agent, &store).unwrap_err();
        assert!(matches!(error, SessionError::UnexpectedRedact));
    }
}
