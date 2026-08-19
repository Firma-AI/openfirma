use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Asserts that the local-exec endpoint observed exactly the expected root command.
///
/// This proves that child stimuli exercised confinement without generating additional governance
/// requests. The recorded request must be valid JSON for a `local.exec` action.
pub(super) fn assert_only_root_governed(governed: &[String], root: &Path) {
    assert_eq!(
        governed.len(),
        1,
        "expected exactly one governance request for the root command: {governed:?}"
    );
    let request: serde_json::Value =
        serde_json::from_str(&governed[0]).expect("governance request must be valid JSON");
    assert_eq!(request["action"], "local.exec");
    assert_eq!(request["executable"], root.to_string_lossy().as_ref());
}

/// Configures the generic profile to allow one root executable through a local governance endpoint.
///
/// The function also points sidecar traffic at `traffic_sock`, allowing each scenario to choose
/// whether that socket is served. It fails if the scaffolded profile no longer has the expected
/// shape rather than silently patching the wrong section.
pub(super) fn patch_local_exec_allowlist(
    config_path: &Path,
    traffic_sock: &Path,
    governance_sock: &Path,
    bash_canonical: &Path,
) {
    let original = std::fs::read_to_string(config_path).expect("read generated firma.toml");
    let anchor = "[run.profiles.generic]\nbackend = \"bwrap\"\n";
    assert!(
        original.contains(anchor),
        "generated firma.toml did not contain the expected generic profile anchor:\n{original}"
    );
    let injected = format!(
        "{anchor}sidecar_endpoint = \"unix:{traffic}\"\n\n\
         [run.profiles.generic.sidecar_local_exec]\n\
         endpoint = \"unix:{governance}\"\n\
         timeout_ms = 2000\n\
         enforce_known_executables = true\n\
         allowed_executables = [\"{bash}\"]\n",
        traffic = traffic_sock.display(),
        governance = governance_sock.display(),
        bash = bash_canonical.display(),
    );
    std::fs::write(config_path, original.replacen(anchor, &injected, 1))
        .expect("write patched firma.toml");
}

/// Starts a detached Unix-socket endpoint that records requests and replies with `allow`.
///
/// Each newline-delimited request is appended to `log`. The endpoint serves until its socket and
/// listener are closed when the test process exits; callers do not receive a shutdown handle.
pub(super) fn spawn_allow_all_endpoint(sock_path: &Path, log: Arc<Mutex<Vec<String>>>) {
    use std::os::unix::net::UnixListener;

    let _ = std::fs::remove_file(sock_path);
    let listener = UnixListener::bind(sock_path)
        .unwrap_or_else(|e| panic!("bind allow-all endpoint at {}: {e}", sock_path.display()));
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut stream) = conn else { continue };
            let mut reader =
                BufReader::new(stream.try_clone().expect("clone allow-all endpoint stream"));
            let mut line = String::new();
            if reader.read_line(&mut line).is_ok() {
                log.lock()
                    .expect("lock governance log")
                    .push(line.trim().to_string());
            }
            let _ = stream.write_all(b"{\"decision\":\"allow\"}\n");
        }
    });
}

/// Sets a generated test tool's Unix permissions to executable by all users.
pub(super) fn set_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = std::fs::metadata(path)
        .expect("stat forbidden-tool")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(path, permissions).expect("chmod forbidden-tool");
}

/// Quotes a path as one POSIX shell word, including paths containing single quotes.
pub(super) fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', r"'\''"))
}

/// Returns the first existing path from an ordered list of platform-specific candidates.
pub(super) fn first_existing(candidates: &[&str]) -> Option<PathBuf> {
    candidates
        .iter()
        .map(PathBuf::from)
        .find(|path| path.exists())
}
