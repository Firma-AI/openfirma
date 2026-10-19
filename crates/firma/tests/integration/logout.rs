//! `firma logout` CLI boundary.

use std::process::Command;

#[cfg(unix)]
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

#[cfg(unix)]
const REVOKE: &str = "/api/agent-flow/v1/authorizations/revoke";
#[cfg(unix)]
const REFRESH_TOKEN: &str = "logout-test-refresh-token";

/// A connection directory inside a fresh temporary directory; the store
/// creates it with private permissions.
fn connection_dir() -> Result<(tempfile::TempDir, std::path::PathBuf), std::io::Error> {
    let root = tempfile::tempdir()?;
    let dir = root.path().join("firma");
    Ok((root, dir))
}

fn logout(connection_dir: &std::path::Path) -> Result<std::process::Output, std::io::Error> {
    Command::new(env!("CARGO_BIN_EXE_firma"))
        .arg("logout")
        .env("FIRMA_CONNECTION_DIR", connection_dir)
        .output()
}

#[cfg(unix)]
fn file_backed_login(
    dir: &std::path::Path,
    origin: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt as _;

    let _store = firma_connection_store::ConnectionStore::open(dir)?;
    let record = serde_json::json!({
        "version": 1,
        "connection_id": "0123456789abcdef0123456789abcdef",
        "origin": origin,
        "development_loopback": true,
        "workspace_id": "wsp_01j0000000e008000000000001",
        "membership_id": "mem_01j0000000e008000000000001",
        "secret": {
            "backend": "file",
            "value": REFRESH_TOKEN,
        },
    });
    let file = dir.join("connection.json");
    std::fs::write(&file, serde_json::to_vec_pretty(&record)?)?;
    std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[test]
fn logout_without_a_saved_login_creates_no_directory() -> Result<(), Box<dyn std::error::Error>> {
    let (_root, dir) = connection_dir()?;

    let output = logout(&dir)?;

    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout)?, "No saved login.\n");
    assert_eq!(output.stderr, [] as [u8; 0]);
    assert!(!dir.exists());
    Ok(())
}

#[cfg(unix)]
#[test]
fn logout_warns_when_an_old_credential_cannot_be_identified()
-> Result<(), Box<dyn std::error::Error>> {
    let (_root, dir) = connection_dir()?;
    let _store = firma_connection_store::ConnectionStore::open(&dir)?;
    std::fs::write(dir.join("connection.json"), "{}")?;

    let output = logout(&dir)?;

    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout)?, "Logged out.\n");
    assert_eq!(
        String::from_utf8(output.stderr)?,
        format!(
            concat!(
                "Warning: a credential for the previous login may remain in the operating system credential store.\n",
                "Warning: the renewable login was removed locally, but server revocation was not confirmed: ",
                "the renewable credential could not be read for server revocation: ",
                "{} is not private to the current user\n",
            ),
            dir.join("connection.json").display(),
        )
    );
    assert!(!dir.join("connection.json").exists());
    Ok(())
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn renewable_logout_is_locally_complete_even_when_server_revocation_fails()
-> Result<(), Box<dyn std::error::Error>> {
    for (status, warns) in [(200, false), (500, true)] {
        let provider = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(REVOKE))
            .respond_with(ResponseTemplate::new(status))
            .mount(&provider)
            .await;
        let (_root, dir) = connection_dir()?;
        file_backed_login(&dir, &format!("{}/", provider.uri()))?;

        let output = logout(&dir)?;

        assert!(output.status.success());
        assert_eq!(String::from_utf8(output.stdout)?, "Logged out.\n");
        let stderr = String::from_utf8(output.stderr)?;
        assert_eq!(
            stderr.contains("server revocation was not confirmed"),
            warns,
            "{stderr}"
        );
        assert!(!dir.join("connection.json").exists());
        let requests = provider
            .received_requests()
            .await
            .ok_or("missing revocation request")?;
        assert_eq!(requests.len(), 1);
        let body = String::from_utf8(requests[0].body.clone())?;
        assert!(body.contains(&format!("token={REFRESH_TOKEN}")));
        assert!(body.contains("token_type_hint=refresh_token"));
    }
    Ok(())
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn failed_local_logout_still_attempts_remote_revocation()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt as _;

    let provider = MockServer::start().await;
    let (_root, dir) = connection_dir()?;
    file_backed_login(&dir, &format!("{}/", provider.uri()))?;
    let revoke_dir = dir.clone();
    Mock::given(method("POST"))
        .and(path(REVOKE))
        .respond_with(move |_: &wiremock::Request| {
            std::fs::set_permissions(&revoke_dir, std::fs::Permissions::from_mode(0o500))
                .expect("make local removal fail after revocation starts");
            ResponseTemplate::new(200)
        })
        .mount(&provider)
        .await;

    let output = logout(&dir)?;

    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    assert!(!output.status.success());
    assert!(dir.join("connection.json").exists());
    let requests = provider
        .received_requests()
        .await
        .ok_or("missing revocation request")?;
    assert_eq!(
        requests.len(),
        1,
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&requests[0].body).contains(&format!("token={REFRESH_TOKEN}")));
    Ok(())
}

#[test]
fn logout_removes_the_saved_connection_and_then_reports_none()
-> Result<(), Box<dyn std::error::Error>> {
    use firma_connection_store::{Connection, ConnectionStore, OriginMode, SecretPolicy};

    let (_root, dir) = connection_dir()?;
    let store = ConnectionStore::open(&dir)?;
    store.exclusive()?.replace(
        &Connection {
            origin: url::Url::parse("https://cp.example/")?,
            origin_mode: OriginMode::Production,
            workspace_id: "wsp_01j0000000e008000000000001".parse()?,
            membership_id: "mem_01j0000000e008000000000001".parse()?,
        },
        None,
        SecretPolicy::NativeOnly,
    )?;

    let first = logout(&dir)?;
    let second = logout(&dir)?;

    assert!(first.status.success());
    assert_eq!(String::from_utf8(first.stdout)?, "Logged out.\n");
    assert!(!dir.join("connection.json").exists());
    assert!(second.status.success());
    assert_eq!(String::from_utf8(second.stdout)?, "No saved login.\n");
    Ok(())
}

#[test]
fn logout_waits_for_another_process_that_holds_the_connection()
-> Result<(), Box<dyn std::error::Error>> {
    use std::time::{Duration, Instant};

    use firma_connection_store::{Connection, ConnectionStore, OriginMode, SecretPolicy};

    let (_root, dir) = connection_dir()?;
    let store = ConnectionStore::open(&dir)?;
    store.exclusive()?.replace(
        &Connection {
            origin: url::Url::parse("https://cp.example/")?,
            origin_mode: OriginMode::Production,
            workspace_id: "wsp_01j0000000e008000000000001".parse()?,
            membership_id: "mem_01j0000000e008000000000001".parse()?,
        },
        None,
        SecretPolicy::NativeOnly,
    )?;
    let held = store.exclusive()?;
    let mut child = Command::new(env!("CARGO_BIN_EXE_firma"))
        .arg("logout")
        .env("FIRMA_CONNECTION_DIR", &dir)
        .stdout(std::process::Stdio::piped())
        .spawn()?;

    let started = Instant::now();
    while started.elapsed() < Duration::from_millis(1500) {
        assert!(
            child.try_wait()?.is_none(),
            "logout finished while another process held the connection"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    drop(held);

    let released = Instant::now();
    while child.try_wait()?.is_none() {
        if released.elapsed() > Duration::from_secs(5) {
            child.kill()?;
            return Err("logout did not finish after the lock was released".into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let output = child.wait_with_output()?;
    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout)?, "Logged out.\n");
    assert!(!dir.join("connection.json").exists());
    Ok(())
}

#[test]
fn logout_rejects_a_relative_connection_directory() -> Result<(), Box<dyn std::error::Error>> {
    let output = logout(std::path::Path::new("relative-dir"))?;

    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8(output.stderr)?.contains("must be an absolute path"),
        "the relative directory was accepted"
    );
    Ok(())
}
