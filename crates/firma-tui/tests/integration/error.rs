use firma_tui::control::{AuditSourceError, ControlError, ErrorMessage, RuntimeError};

#[test]
fn error_message_captures_display_text() {
    let message = ErrorMessage::capture("source failed");

    assert_eq!(message, ErrorMessage::new("source failed"));
    assert_eq!(message.to_string(), "source failed");
}

#[test]
fn runtime_error_keeps_operation_message() {
    let error = RuntimeError::operation("terminal failed");

    assert_eq!(error.to_string(), "terminal failed");
}

#[test]
fn audit_source_errors_render_their_context() {
    let resolve = AuditSourceError::ResolvePath {
        source: ErrorMessage::new("missing config"),
    };
    let parse = AuditSourceError::ParseLine {
        source: ErrorMessage::new("bad json"),
    };

    assert_eq!(
        resolve.to_string(),
        "failed to resolve audit log path: missing config"
    );
    assert_eq!(parse.to_string(), "failed to parse audit line: bad json");
    assert_eq!(
        AuditSourceError::TailerStopped.to_string(),
        "audit tailer stopped"
    );
    assert_eq!(
        AuditSourceError::ForwarderStopped.to_string(),
        "audit forwarder stopped"
    );
    assert_eq!(
        AuditSourceError::operation("forward failed").to_string(),
        "forward failed"
    );
}

#[test]
fn audit_source_error_conversions_keep_message() {
    assert_eq!(
        AuditSourceError::from("literal failure").to_string(),
        "literal failure"
    );
    assert_eq!(
        AuditSourceError::from("owned failure".to_string()).to_string(),
        "owned failure"
    );
}

#[test]
fn control_error_exposes_message_and_optional_path() {
    let runtime = ControlError::runtime("terminal failed");
    let audit = ControlError::audit_source(AuditSourceError::operation("tail failed"));

    assert_eq!(runtime.message(), "terminal failed");
    assert_eq!(audit.message(), "tail failed");
    assert_eq!(runtime.path(), None);
    assert_eq!(audit.path(), None);
    assert_eq!(audit.to_string(), "audit source error: tail failed");
}
