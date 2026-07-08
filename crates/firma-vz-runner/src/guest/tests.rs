use anyhow::Result;

use super::{
    GUEST_HEARTBEAT_FILE, GUEST_RESULT_FILE, GUEST_STDERR_FILE, GUEST_STDIN_FILE,
    GUEST_STDOUT_FILE, GuestResult, GuestResultError,
};

#[test]
fn parses_success_result() -> Result<()> {
    let result = read_guest_result_json(
        r#"{"version":1,"status":"exited","exit_code":0,"signal":null,"error":null}"#,
    )?;
    assert_eq!(result.to_exit_code()?, std::process::ExitCode::SUCCESS);
    Ok(())
}

#[test]
fn rejects_exit_without_code() -> Result<()> {
    let error = read_guest_result_error(
        r#"{"version":1,"status":"exited","exit_code":null,"signal":null,"error":null}"#,
    )?;
    assert!(matches!(error, GuestResultError::MissingExitCode));
    Ok(())
}

#[test]
fn rejects_signal_without_signal_number() -> Result<()> {
    let error = read_guest_result_error(
        r#"{"version":1,"status":"signaled","exit_code":null,"signal":null,"error":null}"#,
    )?;
    assert!(matches!(error, GuestResultError::MissingSignal));
    Ok(())
}

#[test]
fn rejects_error_status_without_error_message() -> Result<()> {
    let error = read_guest_result_error(
        r#"{"version":1,"status":"setup_error","exit_code":null,"signal":null,"error":""}"#,
    )?;
    assert!(matches!(error, GuestResultError::MissingError));
    Ok(())
}

#[test]
fn rejects_unsupported_result_version() -> Result<()> {
    let error = read_guest_result_error(
        r#"{"version":2,"status":"exited","exit_code":0,"signal":null,"error":null}"#,
    )?;
    assert!(matches!(
        error,
        GuestResultError::UnsupportedVersion {
            found: 2,
            supported: 1,
        }
    ));
    Ok(())
}

#[test]
fn reads_guest_result_file() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let path = temp.path().join(GUEST_RESULT_FILE);
    std::fs::write(
        &path,
        r#"{"version":1,"status":"exited","exit_code":7,"signal":null,"error":null}"#,
    )?;

    let result = GuestResult::read(&path)?;

    assert_eq!(result.to_exit_code()?, std::process::ExitCode::from(7));
    Ok(())
}

#[test]
fn read_reports_missing_guest_result_file() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let path = temp.path().join(GUEST_RESULT_FILE);

    let error = GuestResult::read(&path).err().ok_or_else(|| {
        anyhow::anyhow!("missing guest result file should fail with typed read error")
    })?;

    assert!(matches!(error, GuestResultError::Read { path: error_path, .. } if error_path == path));
    Ok(())
}

#[test]
fn read_reports_invalid_guest_result_json() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let path = temp.path().join(GUEST_RESULT_FILE);
    std::fs::write(&path, b"{")?;

    let error = GuestResult::read(&path).err().ok_or_else(|| {
        anyhow::anyhow!("malformed guest result file should fail with typed parse error")
    })?;

    assert!(
        matches!(error, GuestResultError::Parse { path: error_path, .. } if error_path == path)
    );
    Ok(())
}

#[test]
fn exposes_guest_heartbeat_filename() {
    assert_eq!(GUEST_HEARTBEAT_FILE, "guest-heartbeat.json");
}

#[test]
fn exposes_guest_stdio_filenames() {
    assert_eq!(GUEST_STDIN_FILE, "guest-stdin.bin");
    assert_eq!(GUEST_STDOUT_FILE, "guest-stdout.log");
    assert_eq!(GUEST_STDERR_FILE, "guest-stderr.log");
}

fn read_guest_result_json(json: &str) -> Result<GuestResult> {
    let temp = tempfile::tempdir()?;
    let path = temp.path().join(GUEST_RESULT_FILE);
    std::fs::write(&path, json)?;
    Ok(GuestResult::read(&path)?)
}

fn read_guest_result_error(json: &str) -> Result<GuestResultError> {
    let temp = tempfile::tempdir()?;
    let path = temp.path().join(GUEST_RESULT_FILE);
    std::fs::write(&path, json)?;
    GuestResult::read(&path)
        .err()
        .ok_or_else(|| anyhow::anyhow!("guest result should fail validation"))
}
