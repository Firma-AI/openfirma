//! Check 2: sandbox backend availability.

#[cfg(test)]
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
#[cfg(test)]
use std::sync::Mutex;
use std::time::Duration;

use crate::doctor::report::Check;

/// Identifier for one sandbox backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Backend {
    /// Linux bubblewrap isolation.
    Bwrap,
    /// macOS Virtualization framework.
    Vz,
    /// Windows Subsystem for Linux 2.
    Wsl2,
    /// AWS Firecracker micro-VM.
    Firecracker,
}

impl Backend {
    /// Human-readable category label used in the doctor report.
    fn label(self) -> &'static str {
        match self {
            Self::Bwrap => "sandbox bwrap",
            Self::Vz => "sandbox vz",
            Self::Wsl2 => "sandbox wsl2",
            Self::Firecracker => "sandbox firecracker",
        }
    }
}

/// Current OS family — `linux`, `macos`, or `windows`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsFamily {
    /// Linux.
    Linux,
    /// macOS.
    MacOs,
    /// Windows.
    Windows,
}

impl OsFamily {
    /// Returns the OS detected at compile time. Tests pass an explicit value.
    #[must_use]
    pub fn current() -> Self {
        if cfg!(target_os = "linux") {
            Self::Linux
        } else if cfg!(target_os = "macos") {
            Self::MacOs
        } else {
            Self::Windows
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::MacOs => "macos",
            Self::Windows => "windows",
        }
    }
}

/// Result of running `<backend> --version`.
#[derive(Debug, Clone)]
pub struct ProbeOutcome {
    /// `Ok(stdout_first_line)` if the probe ran and exited 0.
    /// `Err(message)` if the binary was missing or exited non-zero.
    pub result: Result<String, String>,
}

/// Future returned by [`Prober::probe`].
pub type ProbeFuture<'a> = Pin<Box<dyn Future<Output = ProbeOutcome> + Send + 'a>>;

/// Pluggable probe. The production impl shells out via `tokio::process::Command`;
/// tests use a deterministic map.
pub trait Prober: Sync {
    /// Run the probe for the given backend.
    fn probe(&self, backend: Backend) -> ProbeFuture<'_>;
}

/// Test prober backed by a `HashMap<Backend, ProbeOutcome>`.
#[cfg(test)]
pub struct MockProber {
    map: Mutex<HashMap<Backend, ProbeOutcome>>,
}

#[cfg(test)]
impl MockProber {
    /// Construct a `MockProber` from a pre-populated outcome map.
    #[must_use]
    pub fn new(map: HashMap<Backend, ProbeOutcome>) -> Self {
        Self {
            map: Mutex::new(map),
        }
    }
}

#[cfg(test)]
impl Prober for MockProber {
    fn probe(&self, backend: Backend) -> ProbeFuture<'_> {
        let outcome = self
            .map
            .lock()
            .ok()
            .and_then(|m| m.get(&backend).cloned())
            .unwrap_or_else(|| ProbeOutcome {
                result: Err("no mock for this backend".into()),
            });
        Box::pin(async move { outcome })
    }
}

/// Returns `true` when `backend` is supported on `os`.
fn supported_on(backend: Backend, os: OsFamily) -> bool {
    matches!(
        (backend, os),
        (Backend::Bwrap | Backend::Firecracker, OsFamily::Linux)
            | (Backend::Vz, OsFamily::MacOs)
            | (Backend::Wsl2, OsFamily::Windows)
    )
}

/// Build the four-element check vector for the current `os` using `prober`.
///
/// Backends that are not supported on `os` are reported as `WARN`. The `vz`
/// backend on macOS is always `WARN` because the Virtualization framework has
/// no CLI probe — reporting `FAIL` would be a false negative.
pub async fn check_with(os: OsFamily, prober: &dyn Prober) -> Vec<Check> {
    let mut out = Vec::with_capacity(4);

    for backend in [
        Backend::Bwrap,
        Backend::Vz,
        Backend::Wsl2,
        Backend::Firecracker,
    ] {
        if !supported_on(backend, os) {
            out.push(Check::warn(
                backend.label(),
                format!("not supported on {}", os.name()),
            ));
            continue;
        }

        // `vz` has no CLI to interrogate; report a deterministic WARN so the
        // check stays informative without producing false negatives.
        if backend == Backend::Vz {
            out.push(Check::warn(
                backend.label(),
                "framework available on macOS 13+; run-time probe not implemented",
            ));
            continue;
        }

        match prober.probe(backend).await.result {
            Ok(version) => {
                out.push(
                    Check::ok(backend.label(), format!("{version} available"))
                        .with_detail("version", version),
                );
            }
            Err(reason) => {
                out.push(Check::fail(backend.label(), reason));
            }
        }
    }

    out
}

/// Production prober that shells out via `tokio::process::Command`.
pub struct CommandProber {
    timeout: Duration,
}

impl CommandProber {
    /// Construct a `CommandProber` that enforces `timeout` per probe.
    #[must_use]
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }

    /// Await `<program> <arg>` to completion, or time out.
    async fn probe_async(
        program: &'static str,
        arg: &'static str,
        timeout: Duration,
    ) -> ProbeOutcome {
        let result = tokio::time::timeout(
            timeout,
            tokio::process::Command::new(program).arg(arg).output(),
        )
        .await;

        let result = match result {
            Ok(Ok(output)) if output.status.success() => {
                let bytes = if output.stdout.is_empty() {
                    &output.stderr
                } else {
                    &output.stdout
                };
                let combined = decode_console_output(bytes);
                let first_line = combined.lines().next().unwrap_or("").trim().to_owned();
                if first_line.is_empty() {
                    Err(format!("{program} {arg} returned no version line"))
                } else {
                    Ok(first_line)
                }
            }
            Ok(Ok(output)) => Err(format!(
                "{program} {arg} exited with status {}",
                output.status
            )),
            Ok(Err(error)) => Err(format!("{program} {arg}: {error}")),
            Err(_elapsed) => Err(format!("{program} {arg}: timed out after {timeout:?}")),
        };

        ProbeOutcome { result }
    }
}

/// Decode raw process output bytes into a string, transparently handling the
/// UTF-16LE payload that some Windows console tools (notably `wsl.exe`) emit
/// to pipes. Strips an optional `FF FE` BOM, otherwise heuristically detects
/// UTF-16LE when most odd-indexed bytes are zero (typical for ASCII-heavy
/// payloads). Falls back to `String::from_utf8_lossy` otherwise.
fn decode_console_output(bytes: &[u8]) -> String {
    let payload = bytes.strip_prefix(&[0xFF, 0xFE]).unwrap_or(bytes);
    if payload.len() >= 2 && payload.len().is_multiple_of(2) && looks_like_utf16_le(payload) {
        let units: Vec<u16> = payload
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        return String::from_utf16_lossy(&units);
    }
    String::from_utf8_lossy(bytes).into_owned()
}

/// Heuristic: ASCII-heavy UTF-16LE has zero bytes at every odd index. Treat the
/// payload as UTF-16LE when at least 80% of odd-indexed bytes are zero, which
/// is robust to occasional non-ASCII code units without misfiring on UTF-8.
fn looks_like_utf16_le(payload: &[u8]) -> bool {
    let pairs = payload.len() / 2;
    if pairs == 0 {
        return false;
    }
    let zero_high_bytes = payload.chunks_exact(2).filter(|c| c[1] == 0x00).count();
    zero_high_bytes * 5 >= pairs * 4
}

impl Prober for CommandProber {
    fn probe(&self, backend: Backend) -> ProbeFuture<'_> {
        let timeout = self.timeout;
        Box::pin(async move {
            match backend {
                Backend::Bwrap => Self::probe_async("bwrap", "--version", timeout).await,
                Backend::Wsl2 => Self::probe_async("wsl.exe", "--version", timeout).await,
                Backend::Firecracker => {
                    Self::probe_async("firecracker", "--version", timeout).await
                }
                Backend::Vz => ProbeOutcome {
                    result: Err("vz has no command-line probe".into()),
                },
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doctor::report::Status;

    fn outcome_ok(line: &str) -> ProbeOutcome {
        ProbeOutcome {
            result: Ok(line.into()),
        }
    }

    fn outcome_err(line: &str) -> ProbeOutcome {
        ProbeOutcome {
            result: Err(line.into()),
        }
    }

    #[tokio::test]
    async fn linux_only_probes_bwrap_and_firecracker() {
        let mut m = HashMap::new();
        m.insert(Backend::Bwrap, outcome_ok("bubblewrap 0.8.0"));
        m.insert(Backend::Firecracker, outcome_ok("Firecracker v1.7.0"));
        let checks = check_with(OsFamily::Linux, &MockProber::new(m)).await;
        assert_eq!(checks.len(), 4);
        let by_label: HashMap<&str, &Check> = checks.iter().map(|c| (c.category, c)).collect();
        assert_eq!(by_label["sandbox bwrap"].status, Status::Ok);
        assert_eq!(by_label["sandbox firecracker"].status, Status::Ok);
        assert_eq!(by_label["sandbox vz"].status, Status::Warn);
        assert_eq!(by_label["sandbox wsl2"].status, Status::Warn);
        assert!(
            by_label["sandbox vz"]
                .reason
                .contains("not supported on linux")
        );
        assert!(
            by_label["sandbox wsl2"]
                .reason
                .contains("not supported on linux")
        );
    }

    #[tokio::test]
    async fn linux_missing_bwrap_is_fail() {
        let mut m = HashMap::new();
        m.insert(Backend::Bwrap, outcome_err("bwrap: not found in PATH"));
        m.insert(Backend::Firecracker, outcome_ok("Firecracker v1.7.0"));
        let checks = check_with(OsFamily::Linux, &MockProber::new(m)).await;
        let bwrap = checks
            .iter()
            .find(|c| c.category == "sandbox bwrap")
            .expect("bwrap check must be present");
        assert_eq!(bwrap.status, Status::Fail);
        assert!(bwrap.reason.contains("not found in PATH"));
    }

    #[tokio::test]
    async fn macos_reports_vz_warn_and_others_unsupported() {
        let checks = check_with(OsFamily::MacOs, &MockProber::new(HashMap::new())).await;
        let by_label: HashMap<&str, &Check> = checks.iter().map(|c| (c.category, c)).collect();
        assert_eq!(by_label["sandbox vz"].status, Status::Warn);
        assert!(by_label["sandbox vz"].reason.contains("macOS 13+"));
        assert_eq!(by_label["sandbox bwrap"].status, Status::Warn);
        assert_eq!(by_label["sandbox firecracker"].status, Status::Warn);
        assert_eq!(by_label["sandbox wsl2"].status, Status::Warn);
    }

    #[test]
    fn decode_console_output_handles_utf16_with_bom() {
        let mut bytes = vec![0xFF, 0xFE];
        for c in "hi".encode_utf16() {
            bytes.extend_from_slice(&c.to_le_bytes());
        }
        assert_eq!(decode_console_output(&bytes), "hi");
    }

    #[test]
    fn decode_console_output_detects_bomless_utf16le() {
        let bytes: Vec<u8> = "WSL version: 2.7.3.0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(decode_console_output(&bytes), "WSL version: 2.7.3.0");
    }

    #[test]
    fn decode_console_output_passes_utf8_through() {
        let bytes = b"bubblewrap 0.8.0\n";
        assert_eq!(decode_console_output(bytes), "bubblewrap 0.8.0\n");
    }

    #[tokio::test]
    async fn windows_only_probes_wsl2() {
        let mut m = HashMap::new();
        m.insert(Backend::Wsl2, outcome_ok("WSL version: 2.0.0"));
        let checks = check_with(OsFamily::Windows, &MockProber::new(m)).await;
        let wsl2 = checks
            .iter()
            .find(|c| c.category == "sandbox wsl2")
            .expect("wsl2 check must be present");
        assert_eq!(wsl2.status, Status::Ok);
        assert!(wsl2.reason.contains("2.0.0"));
    }
}
