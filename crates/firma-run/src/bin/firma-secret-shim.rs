//! `firma-secret-shim` — the in-sandbox stdio interposition shim.
//!
//! Bind-mounted over a configured executable, this couriers the wrapped tool's
//! stdio to the out-of-sandbox broker (which rewrites secrets) and then runs the
//! real tool with its stdio routed through the broker. See
//! `docs/architecture/secrets-interception.md`.
//!
//! Fail-closed: if the broker is unreachable or the environment is not set up,
//! the shim exits non-zero **without** running the tool, so an unmediated tool
//! never runs.

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    match imp::run() {
        Ok(code) => std::process::ExitCode::from(u8::try_from(code).unwrap_or(1)),
        Err(error) => {
            eprintln!("firma-secret-shim: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(not(unix))]
fn main() -> std::process::ExitCode {
    // The shim relies on Unix socket fd-passing; on other platforms it fails
    // closed so a shimmed tool is never run unmediated.
    eprintln!("firma-secret-shim: secret mediation requires a Unix platform");
    std::process::ExitCode::FAILURE
}

#[cfg(unix)]
mod imp {
    use std::ffi::OsStr;
    use std::io;
    use std::os::fd::{AsFd, OwnedFd};
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::ExitStatusExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};

    use firma_run::secret::shim::{BROKER_SOCK_ENV, REAL_DIR_ENV, courier};

    /// Set up the socketpairs, courier the descriptors, run the real tool, and
    /// return its exit code.
    pub fn run() -> io::Result<i32> {
        let sock = required_env(BROKER_SOCK_ENV)?;
        let real_dir = required_env(REAL_DIR_ENV)?;
        let argv: Vec<String> = std::env::args().collect();
        let real = resolve_real(Path::new(&real_dir), argv.first().map(String::as_str))?;

        // One socketpair per direction. The tool end becomes the tool's stdio;
        // the broker end is couriered so the broker reads/writes plaintext.
        let (in_broker, in_tool) = UnixStream::pair()?;
        let (out_broker, out_tool) = UnixStream::pair()?;

        // Courier before spawning so the broker holds the descriptors before the
        // tool produces any output. The agent legs are the shim's own stdio.
        courier(
            Path::new(&sock),
            &argv,
            io::stdin().as_fd(),
            in_broker.as_fd(),
            out_broker.as_fd(),
            io::stdout().as_fd(),
        )?;

        let mut command = Command::new(&real);
        command
            .args(&argv[1..])
            .stdin(Stdio::from(OwnedFd::from(in_tool)))
            .stdout(Stdio::from(OwnedFd::from(out_tool)));
        // stderr is not mediated; leave it connected to the agent.
        let mut child = command.spawn()?;

        // The broker holds duplicates of the couriered descriptors now.
        drop(in_broker);
        drop(out_broker);

        let status = child.wait()?;
        Ok(status
            .code()
            .unwrap_or_else(|| 128 + status.signal().unwrap_or(0)))
    }

    fn required_env(key: &str) -> io::Result<String> {
        std::env::var(key)
            .map_err(|_| io::Error::other(format!("missing required environment variable {key}")))
    }

    /// Resolve the real binary as `<real_dir>/<basename(argv0)>`.
    fn resolve_real(real_dir: &Path, argv0: Option<&str>) -> io::Result<PathBuf> {
        let argv0 = argv0.ok_or_else(|| io::Error::other("empty argv"))?;
        let name = Path::new(argv0)
            .file_name()
            .ok_or_else(|| io::Error::other("argv[0] has no file name"))?;
        let real = real_dir.join(name);
        if real.file_name() == Some(OsStr::new(name)) && real.exists() {
            Ok(real)
        } else {
            Err(io::Error::other(format!(
                "real binary not found for {}",
                Path::new(argv0).display()
            )))
        }
    }
}
