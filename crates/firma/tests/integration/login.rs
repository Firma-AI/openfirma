//! `firma login` CLI boundary, against a test double of the Control Plane's
//! token and `current` endpoints. The real Authority is covered by the Firma
//! Team end-to-end suite.

use std::process::Command;

#[cfg(unix)]
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

#[cfg(unix)]
const TOKEN: &str = "/api/agent-flow/v1/authorizations/token";
#[cfg(unix)]
const CURRENT: &str = "/api/agent-flow/v1/sessions/workspace/current";
#[cfg(unix)]
const REVOKE: &str = "/api/agent-flow/v1/authorizations/revoke";
#[cfg(unix)]
const WORKSPACE: &str = "wsp_01j0000000e008000000000001";
#[cfg(unix)]
const MEMBERSHIP: &str = "mem_01j0000000e008000000000001";
#[cfg(unix)]
const ACCESS_TOKEN: &str = "opaque-test-access-token";

#[cfg(unix)]
struct KillOnDropChild(std::process::Child);

#[cfg(unix)]
impl Drop for KillOnDropChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The requests the CLI made. On macOS the real browser may open the
/// authorization URL on this server, so its requests are left out.
#[cfg(unix)]
async fn cli_requests(
    provider: &MockServer,
) -> Result<Vec<wiremock::Request>, Box<dyn std::error::Error>> {
    Ok(provider
        .received_requests()
        .await
        .ok_or("missing requests")?
        .into_iter()
        .filter(|request| [TOKEN, CURRENT].contains(&request.url.path()))
        .collect())
}

/// A Control Plane double whose token endpoint answers with `token`.
#[cfg(unix)]
async fn control_plane(token: ResponseTemplate) -> MockServer {
    control_plane_with(
        token,
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "workspace_id": WORKSPACE,
            "membership_id": MEMBERSHIP,
        })),
    )
    .await
}

#[cfg(unix)]
async fn control_plane_with(token: ResponseTemplate, current: ResponseTemplate) -> MockServer {
    let provider = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(TOKEN))
        .respond_with(token)
        .mount(&provider)
        .await;
    Mock::given(method("GET"))
        .and(path(CURRENT))
        .respond_with(current)
        .mount(&provider)
        .await;
    Mock::given(method("POST"))
        .and(path(REVOKE))
        .respond_with(ResponseTemplate::new(200))
        .mount(&provider)
        .await;
    provider
}

#[cfg(unix)]
fn granted() -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(serde_json::json!({
        "access_token": ACCESS_TOKEN,
        "refresh_token": "renewable-test-secret",
        "token_type": "Bearer",
        "expires_in": 600,
        "workspace_id": WORKSPACE,
        "membership_id": MEMBERSHIP,
    }))
}

/// A private directory for the saved connection, so no test touches the
/// user's real one.
#[cfg(unix)]
fn connection_dir() -> Result<tempfile::TempDir, Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt as _;

    Ok(tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()?)
}

/// Runs a loopback login saving into `connection_dir`, answering its
/// callback with `response` plus the request's `state`, and returns the exit
/// status and all output.
#[cfg(unix)]
async fn loopback_login(
    provider: &MockServer,
    connection_dir: &std::path::Path,
    response: (&str, &str),
) -> Result<(std::process::ExitStatus, String, String), Box<dyn std::error::Error>> {
    loopback_login_with(
        provider,
        connection_dir,
        response,
        &["--allow-plaintext-refresh-token"],
    )
    .await
}

#[cfg(unix)]
async fn loopback_login_with(
    provider: &MockServer,
    connection_dir: &std::path::Path,
    response: (&str, &str),
    extra_args: &[&str],
) -> Result<(std::process::ExitStatus, String, String), Box<dyn std::error::Error>> {
    use tokio::io::AsyncReadExt as _;

    let (child, mut reader) =
        start_loopback_login_with(provider, connection_dir, response, extra_args).await?;
    let output = tokio::time::timeout(std::time::Duration::from_secs(20), child.wait_with_output())
        .await??;
    let mut stderr = String::new();
    reader.read_to_string(&mut stderr).await?;
    Ok((output.status, String::from_utf8(output.stdout)?, stderr))
}

#[cfg(unix)]
async fn start_loopback_login(
    provider: &MockServer,
    connection_dir: &std::path::Path,
    response: (&str, &str),
) -> Result<
    (
        tokio::process::Child,
        tokio::io::BufReader<tokio::process::ChildStderr>,
    ),
    Box<dyn std::error::Error>,
> {
    start_loopback_login_with(
        provider,
        connection_dir,
        response,
        &["--allow-plaintext-refresh-token"],
    )
    .await
}

#[cfg(unix)]
async fn start_loopback_login_with(
    provider: &MockServer,
    connection_dir: &std::path::Path,
    response: (&str, &str),
    extra_args: &[&str],
) -> Result<
    (
        tokio::process::Child,
        tokio::io::BufReader<tokio::process::ChildStderr>,
    ),
    Box<dyn std::error::Error>,
> {
    use tokio::io::AsyncBufReadExt as _;

    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_firma"))
        .args([
            "login",
            "--control-plane-origin",
            &provider.uri(),
            "--development-loopback",
        ])
        .args(extra_args)
        .env("FIRMA_LOGIN_NO_BROWSER", "1")
        .env("FIRMA_CONNECTION_DIR", connection_dir)
        .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/dev/null")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    // The URL goes to stderr, so a redirected stdout never records its `state`.
    let stderr = child.stderr.take().ok_or("missing stderr")?;
    let mut reader = tokio::io::BufReader::new(stderr);
    let mut authorization_url = String::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        reader.read_line(&mut authorization_url),
    )
    .await??;
    let url = url::Url::parse(authorization_url.trim())?;
    let fields: std::collections::BTreeMap<_, _> = url.query_pairs().into_owned().collect();
    assert_eq!(
        fields.get("scope").map(String::as_str),
        Some("offline_access")
    );
    let mut callback = url::Url::parse(fields.get("redirect_uri").ok_or("missing callback")?)?;
    callback
        .query_pairs_mut()
        .append_pair(response.0, response.1)
        .append_pair("state", fields.get("state").ok_or("missing state")?);
    reqwest::get(callback).await?;
    Ok((child, reader))
}

#[cfg(unix)]
#[tokio::test]
async fn login_reports_success_only_after_an_authenticated_workspace_request()
-> Result<(), Box<dyn std::error::Error>> {
    let provider = control_plane(granted()).await;
    let dir = connection_dir()?;
    let code = "A".repeat(43);

    let (status, stdout, stderr) = loopback_login(&provider, dir.path(), ("code", &code)).await?;

    assert!(status.success(), "{stderr}");
    assert!(stdout.contains(&format!(
        "Logged in to Workspace {WORKSPACE} as Membership {MEMBERSHIP}."
    )));
    assert!(stdout.contains(&format!("Saved this login to {}.", dir.path().display())));
    assert!(!stdout.contains(ACCESS_TOKEN) && !stderr.contains(ACCESS_TOKEN));
    assert!(
        !stdout.contains("state="),
        "the login URL stays off stdout: {stdout}"
    );
    let requests = cli_requests(&provider).await?;
    let paths: Vec<_> = requests.iter().map(|request| request.url.path()).collect();
    assert_eq!(paths, [TOKEN, CURRENT]);
    assert!(String::from_utf8(requests[0].body.clone())?.contains(&format!("code={code}&")));
    assert_eq!(
        requests[1].headers["authorization"],
        format!("Bearer {ACCESS_TOKEN}").as_str()
    );
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn ctrl_c_during_a_locked_save_waits_for_the_commit() -> Result<(), Box<dyn std::error::Error>>
{
    use std::time::Duration;

    use firma_connection_store::ConnectionStore;
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;
    use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _};

    let provider = control_plane(granted()).await;
    let dir = connection_dir()?;
    let store = ConnectionStore::open(dir.path())?;
    let held = store.shared()?;
    let code = "A".repeat(43);
    let (mut child, mut reader) =
        start_loopback_login(&provider, dir.path(), ("code", &code)).await?;
    let pid = child.id().ok_or("login has no process ID")?;
    let mut saving_line = String::new();
    tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut saving_line)).await??;
    assert_eq!(saving_line, "Saving this login...\n");
    kill(Pid::from_raw(pid.try_into()?), Signal::SIGINT)?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        child.try_wait()?.is_none(),
        "login exited before the commit"
    );
    drop(held);

    let output = tokio::time::timeout(Duration::from_secs(10), child.wait_with_output()).await??;
    let mut stderr = String::new();
    reader.read_to_string(&mut stderr).await?;
    assert!(output.status.success(), "{stderr}");
    assert!(stderr.contains("Finishing the local save; please wait."));
    assert!(String::from_utf8(output.stdout)?.contains("Logged in to Workspace"));
    assert!(dir.path().join("connection.json").exists());
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn a_denial_or_a_rejected_code_ends_the_login() -> Result<(), Box<dyn std::error::Error>> {
    let rejected =
        ResponseTemplate::new(400).set_body_json(serde_json::json!({ "error": "invalid_grant" }));
    let code = "A".repeat(43);
    for (case, token, current, response, requests, revocations, message) in [
        (
            "denied",
            granted(),
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "workspace_id": WORKSPACE,
                "membership_id": MEMBERSHIP,
            })),
            ("error", "access_denied"),
            0,
            0,
            "the login was denied in the browser",
        ),
        (
            "invalid grant",
            rejected,
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "workspace_id": WORKSPACE,
                "membership_id": MEMBERSHIP,
            })),
            ("code", code.as_str()),
            1,
            0,
            "the login code expired, was already used, or does not match",
        ),
        (
            "identity mismatch",
            granted(),
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "workspace_id": WORKSPACE,
                "membership_id": "mem_01j0000000e008000000000002",
            })),
            ("code", code.as_str()),
            2,
            1,
            "authenticated Workspace request failed",
        ),
    ] {
        let provider = control_plane_with(token, current).await;
        let dir = connection_dir()?;

        let (status, stdout, stderr) = loopback_login(&provider, dir.path(), response).await?;

        assert!(!status.success(), "{case}");
        assert!(!dir.path().join("connection.json").exists(), "{case}");
        assert!(!stdout.contains("Logged in"), "{case}");
        assert!(
            stderr.starts_with("[ERR]  ") && stderr.contains(message),
            "{case}: {stderr}"
        );
        assert!(!stdout.contains(&code) && !stderr.contains(&code), "{case}");
        let received = cli_requests(&provider).await?;
        assert_eq!(received.len(), requests, "{case}");
        let received = provider
            .received_requests()
            .await
            .ok_or("missing Control Plane requests")?;
        let revocation_requests: Vec<_> = received
            .iter()
            .filter(|request| request.url.path() == REVOKE)
            .collect();
        assert_eq!(revocation_requests.len(), revocations, "{case}");
        if let Some(request) = revocation_requests.first() {
            assert!(
                String::from_utf8(request.body.clone())?.contains("token=renewable-test-secret"),
                "{case}"
            );
        }
    }
    Ok(())
}

#[test]
fn terminal_code_rejects_noninteractive_input() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_firma"))
        .args([
            "login",
            "--control-plane-origin",
            "https://example.test",
            "--terminal-code",
        ])
        .output()?;
    assert!(!output.status.success());
    assert_eq!(
        String::from_utf8(output.stderr)?,
        "[ERR]  terminal-code login requires an interactive terminal\n"
    );
    Ok(())
}

/// A `firma login --terminal-code` waiting at its hidden prompt on a PTY.
#[cfg(unix)]
struct PromptedLogin {
    child: KillOnDropChild,
    terminal: std::fs::File,
    settings: std::os::fd::OwnedFd,
    transcript: Vec<u8>,
}

#[cfg(unix)]
impl PromptedLogin {
    /// Starts the login, saving into `connection_dir`, and returns once the
    /// prompt is shown with echo off.
    fn start(
        origin: &str,
        connection_dir: &std::path::Path,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        use std::process::Stdio;

        let pty = nix::pty::openpty(None, None)?;
        let child = KillOnDropChild(
            Command::new(env!("CARGO_BIN_EXE_firma"))
                .args([
                    "login",
                    "--control-plane-origin",
                    origin,
                    "--development-loopback",
                    "--terminal-code",
                    "--allow-plaintext-refresh-token",
                ])
                .env("FIRMA_LOGIN_NO_BROWSER", "1")
                .env("FIRMA_CONNECTION_DIR", connection_dir)
                .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/dev/null")
                .stdin(Stdio::from(pty.slave.try_clone()?))
                .stderr(Stdio::from(pty.slave.try_clone()?))
                .stdout(Stdio::piped())
                .spawn()?,
        );
        let mut login = Self {
            child,
            terminal: std::fs::File::from(pty.master),
            settings: pty.slave,
            transcript: Vec::new(),
        };
        for _ in 0..20 {
            login.drain(500)?;
            if login
                .transcript_text()
                .contains("Paste one-time login code")
                && !login.echo()?
            {
                return Ok(login);
            }
        }
        Err(format!("no hidden prompt: {}", login.transcript_text()).into())
    }

    fn echo(&self) -> Result<bool, Box<dyn std::error::Error>> {
        Ok(nix::sys::termios::tcgetattr(&self.settings)?
            .local_flags
            .contains(nix::sys::termios::LocalFlags::ECHO))
    }

    /// Reads whatever the terminal shows within `timeout_ms`.
    fn drain(&mut self, timeout_ms: u16) -> Result<(), Box<dyn std::error::Error>> {
        use nix::poll::{PollFd, PollFlags, poll};
        use std::io::Read as _;
        use std::os::fd::AsFd as _;

        let mut fds = [PollFd::new(self.terminal.as_fd(), PollFlags::POLLIN)];
        if poll(&mut fds, timeout_ms)? > 0 {
            let mut chunk = [0_u8; 256];
            if let Ok(read) = self.terminal.read(&mut chunk) {
                self.transcript.extend_from_slice(&chunk[..read]);
            }
        }
        Ok(())
    }

    fn transcript_text(&self) -> String {
        String::from_utf8_lossy(&self.transcript).into_owned()
    }

    fn wait(&mut self) -> Result<std::process::ExitStatus, Box<dyn std::error::Error>> {
        use wait_timeout::ChildExt as _;
        Ok(self
            .child
            .0
            .wait_timeout(std::time::Duration::from_secs(20))?
            .ok_or("login did not exit")?)
    }
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_terminal_code_prompt_hides_the_code_and_completes_the_login()
-> Result<(), Box<dyn std::error::Error>> {
    use std::io::{Read as _, Write as _};

    let provider = control_plane(granted()).await;
    let dir = connection_dir()?;
    let origin = provider.uri();
    let code = "B".repeat(43);
    let (status, stdout, transcript) = tokio::task::spawn_blocking({
        let code = code.clone();
        let dir = dir.path().to_path_buf();
        move || -> Result<_, String> {
            let mut login = PromptedLogin::start(&origin, &dir).map_err(|e| e.to_string())?;
            login
                .terminal
                .write_all(format!("{code}\n").as_bytes())
                .map_err(|e| e.to_string())?;
            let status = login.wait().map_err(|e| e.to_string())?;
            let mut stdout = String::new();
            login
                .child
                .0
                .stdout
                .take()
                .ok_or("missing stdout")?
                .read_to_string(&mut stdout)
                .map_err(|e| e.to_string())?;
            login.drain(100).map_err(|e| e.to_string())?;
            Ok((status, stdout, login.transcript_text()))
        }
    })
    .await??;

    assert!(status.success(), "{transcript}");
    assert!(stdout.contains(&format!("Logged in to Workspace {WORKSPACE}")));
    assert!(!stdout.contains(&code));
    assert!(!transcript.contains(&code));
    let requests = cli_requests(&provider).await?;
    assert!(String::from_utf8(requests[0].body.clone())?.contains(&format!("code={code}&")));
    Ok(())
}

#[cfg(unix)]
#[test]
fn ctrl_c_at_the_code_prompt_gives_back_an_echoing_terminal()
-> Result<(), Box<dyn std::error::Error>> {
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;

    let dir = connection_dir()?;
    let mut login = PromptedLogin::start("http://127.0.0.1:9", dir.path())?;
    let pid = i32::try_from(login.child.0.id())?;
    kill(Pid::from_raw(pid), Signal::SIGINT)?;
    let status = login.wait()?;

    assert_eq!(status.code(), Some(130));
    assert!(login.echo()?, "the terminal was left without echo");
    Ok(())
}

#[test]
fn login_rejects_plain_http_without_the_development_switch()
-> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_firma"))
        .args(["login", "--control-plane-origin", "http://127.0.0.1:8080"])
        .output()?;
    assert!(!output.status.success());
    assert_eq!(
        String::from_utf8(output.stderr)?,
        "[ERR]  invalid control plane origin: control-plane origin must use HTTPS\n"
    );
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn login_refuses_when_the_saved_record_is_unreadable()
-> Result<(), Box<dyn std::error::Error>> {
    let provider = control_plane(granted()).await;
    let dir = connection_dir()?;
    std::fs::write(dir.path().join("connection.json"), "{}")?;
    let output = rejected_login(&provider, dir.path()).await?;
    let status = output.status;
    let stdout = String::from_utf8(output.stdout)?;
    let stderr = String::from_utf8(output.stderr)?;

    assert_eq!(status.code(), Some(1));
    assert!(!stdout.contains("Logged in to Workspace"), "{stdout}");
    assert!(
        stderr.contains("could not inspect the saved login")
            && stderr.contains("run firma logout before logging in again"),
        "{stderr}"
    );
    assert_eq!(std::fs::read(dir.path().join("connection.json"))?, b"{}");
    let requests = provider
        .received_requests()
        .await
        .ok_or("missing request log")?;
    assert!(
        requests.is_empty(),
        "must reject before starting authorization"
    );
    Ok(())
}

#[cfg(unix)]
async fn rejected_login(
    provider: &MockServer,
    dir: &std::path::Path,
) -> Result<std::process::Output, Box<dyn std::error::Error>> {
    Ok(tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::process::Command::new(env!("CARGO_BIN_EXE_firma"))
            .args([
                "login",
                "--control-plane-origin",
                &provider.uri(),
                "--development-loopback",
            ])
            .env("FIRMA_LOGIN_NO_BROWSER", "1")
            .env("FIRMA_CONNECTION_DIR", dir)
            .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/dev/null")
            .kill_on_drop(true)
            .output(),
    )
    .await??)
}

#[cfg(unix)]
#[tokio::test]
async fn login_saves_privately_and_requires_logout_before_switching()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt as _;

    let first = control_plane(granted()).await;
    let dir = connection_dir()?;
    let code = "A".repeat(43);
    let (status, _, stderr) = loopback_login(&first, dir.path(), ("code", &code)).await?;
    assert!(status.success(), "{stderr}");
    let file = dir.path().join("connection.json");
    let saved: serde_json::Value = serde_json::from_slice(&std::fs::read(&file)?)?;
    assert_eq!(saved["origin"], format!("{}/", first.uri()));
    assert_eq!(saved["development_loopback"], true);
    assert_eq!(saved["workspace_id"], WORKSPACE);
    assert_eq!(saved["membership_id"], MEMBERSHIP);
    assert_eq!(
        std::fs::metadata(&file)?.permissions().mode() & 0o777,
        0o600
    );
    let backend = saved["secret"]["backend"]
        .as_str()
        .ok_or("missing secret backend")?;
    if cfg!(target_os = "linux") {
        assert_eq!(
            backend, "file",
            "the disabled D-Bus service forces file fallback on Linux"
        );
    }
    if backend == "file" {
        assert_eq!(saved["secret"]["value"], "renewable-test-secret");
    } else {
        assert_eq!(backend, "native");
        assert!(saved["secret"].get("value").is_none());
    }

    let second = control_plane(granted()).await;
    let output = rejected_login(&second, dir.path()).await?;
    let status = output.status;
    let stdout = String::from_utf8(output.stdout)?;
    let stderr = String::from_utf8(output.stderr)?;

    assert_eq!(status.code(), Some(1));
    assert!(!stdout.contains("Logged in to Workspace"), "{stdout}");
    assert!(
        stderr.contains("a login is already saved; run firma logout before logging in again"),
        "{stderr}"
    );
    let saved: serde_json::Value = serde_json::from_slice(&std::fs::read(&file)?)?;
    assert_eq!(saved["origin"], format!("{}/", first.uri()));
    let second_requests = second
        .received_requests()
        .await
        .ok_or("missing second Control Plane requests")?;
    assert!(
        second_requests.is_empty(),
        "repeated login must not mint an unused family"
    );
    let entries = std::fs::read_dir(dir.path())?.count();
    assert_eq!(entries, 2, "connection.json and connection.lock only");
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn failed_first_save_reports_the_error_without_compensating_revocation()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = connection_dir()?;
    let code = "A".repeat(43);
    let provider = control_plane(granted()).await;
    let save_dir = dir.path().to_path_buf();
    Mock::given(method("GET"))
        .and(path(CURRENT))
        .respond_with(move |_: &wiremock::Request| {
            std::fs::set_permissions(&save_dir, std::fs::Permissions::from_mode(0o770))
                .expect("make save fail after successful authentication");
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "workspace_id": WORKSPACE, "membership_id": MEMBERSHIP,
            }))
        })
        .with_priority(1)
        .mount(&provider)
        .await;

    let (status, stdout, stderr) = loopback_login(&provider, dir.path(), ("code", &code)).await?;

    assert_eq!(status.code(), Some(1));
    assert!(!stdout.contains("Logged in to Workspace"), "{stdout}");
    assert!(!stdout.contains("Saved this login"), "{stdout}");
    assert!(
        stderr.contains("could not save the login")
            && stderr.contains("is not private to the current user"),
        "{stderr}"
    );
    assert!(!dir.path().join("connection.json").exists());
    let requests = provider
        .received_requests()
        .await
        .ok_or("missing login requests")?;
    assert!(!requests.iter().any(|request| request.url.path() == REVOKE));
    Ok(())
}
