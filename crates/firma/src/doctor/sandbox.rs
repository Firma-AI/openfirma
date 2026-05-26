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

/// Snapshot of the host's sandbox-relevant capabilities.
///
/// Mirrors the inputs `firma run` uses when it auto-selects and preflights a
/// backend, so the doctor's verdicts match what the runtime would actually do
/// on this host rather than a static OS → backend table.
#[derive(Debug, Clone)]
pub struct HostProbe {
    /// OS family detected at compile time.
    pub os: OsFamily,
    /// Whether the process is running inside any WSL environment.
    pub wsl: bool,
    /// `Some(sysctl_path)` when unprivileged user-namespace creation is blocked
    /// (so bubblewrap cannot construct a sandbox), `None` otherwise.
    pub userns_restricted: Option<String>,
}

impl HostProbe {
    /// Probe the current host using the same detectors `firma run` relies on.
    #[must_use]
    pub fn current() -> Self {
        Self {
            os: OsFamily::current(),
            wsl: firma_run::backend::platform::detect_wsl().is_wsl(),
            userns_restricted: firma_run::backend::platform::userns_restricted(),
        }
    }
}

/// Build the four-element check vector for `host` using `prober`.
///
/// Verdicts mirror what `firma run` would do on this host (see
/// `firma_run::config::resolve_backend` and the bwrap preflight): the backend
/// the runtime would auto-select reports its real capability, backends the
/// runtime would refuse here do not report `OK`, and backends that simply do
/// not apply to this host report `WARN` (informational, never `OK`).
pub async fn check_with(host: &HostProbe, prober: &dyn Prober) -> Vec<Check> {
    let mut out = Vec::with_capacity(4);
    for backend in [
        Backend::Bwrap,
        Backend::Vz,
        Backend::Wsl2,
        Backend::Firecracker,
    ] {
        out.push(check_backend(backend, host, prober).await);
    }
    out
}

/// Verdict for one backend on `host`, matching runtime selection/preflight.
async fn check_backend(backend: Backend, host: &HostProbe, prober: &dyn Prober) -> Check {
    let label = backend.label();
    match (backend, host.os) {
        // -- Linux ----------------------------------------------------------
        (Backend::Bwrap, OsFamily::Linux) => check_bwrap(label, host, prober).await,
        (Backend::Wsl2, OsFamily::Linux) => {
            if host.wsl {
                // The runtime auto-selects wsl2 here; reflect it as usable
                // rather than "not supported on linux".
                Check::ok(
                    label,
                    "active backend on this WSL host (selected by firma run)",
                )
            } else {
                Check::warn(label, "not used on native Linux (runtime selects bwrap)")
            }
        }
        (Backend::Vz, OsFamily::Linux) => Check::warn(label, "not used on linux"),
        // firecracker is never auto-selected on Linux (bwrap is); report it as
        // an optional backend so a missing binary is not a false failure.
        (Backend::Firecracker, OsFamily::Linux) => probe_optional(label, backend, prober).await,
        // wsl2 on Windows is the selected backend, so probe it for real.
        (Backend::Wsl2, OsFamily::Windows) => probe_to_check(label, backend, prober).await,
        // -- macOS ----------------------------------------------------------
        (Backend::Vz, OsFamily::MacOs) => Check::warn(
            label,
            "framework available on macOS 13+; run-time probe not implemented",
        ),
        (_, OsFamily::MacOs) => Check::warn(label, "not used on macos"),
        // -- Windows --------------------------------------------------------
        (_, OsFamily::Windows) => Check::warn(label, "not used on windows"),
    }
}

/// bwrap verdict on Linux, matching `linux_bwrap::preflight_host_support`:
/// refused under WSL and when unprivileged user namespaces are restricted.
async fn check_bwrap(label: &'static str, host: &HostProbe, prober: &dyn Prober) -> Check {
    if host.wsl {
        return Check::warn(
            label,
            "not usable under WSL: unprivileged user namespaces unavailable; \
             firma run uses the wsl2 backend on this host",
        );
    }
    if let Some(sysctl) = &host.userns_restricted {
        return Check::fail(
            label,
            format!(
                "user namespace creation restricted ({sysctl}=0); \
                 bubblewrap cannot construct a sandbox until this is enabled"
            ),
        );
    }
    probe_to_check(label, Backend::Bwrap, prober).await
}

/// Run the CLI probe for `backend` and map the outcome to a `Check`. A failed
/// probe is a `FAIL`: used for the backend the runtime would actually select.
async fn probe_to_check(label: &'static str, backend: Backend, prober: &dyn Prober) -> Check {
    match prober.probe(backend).await.result {
        Ok(version) => {
            Check::ok(label, format!("{version} available")).with_detail("version", version)
        }
        Err(reason) => Check::fail(label, reason),
    }
}

/// Probe an optional backend the runtime never auto-selects on this host. A
/// failed probe is a `WARN`, not a `FAIL` — its absence is expected.
async fn probe_optional(label: &'static str, backend: Backend, prober: &dyn Prober) -> Check {
    prober.probe(backend).await.result.map_or_else(
        |_| Check::warn(label, "optional; not auto-selected on this host"),
        |version| Check::ok(label, format!("{version} available")).with_detail("version", version),
    )
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

    /// Native (non-WSL, unrestricted) host on `os`.
    fn host(os: OsFamily) -> HostProbe {
        HostProbe {
            os,
            wsl: false,
            userns_restricted: None,
        }
    }

    fn by_label(checks: &[Check]) -> HashMap<&str, &Check> {
        checks.iter().map(|c| (c.category, c)).collect()
    }

    #[tokio::test]
    async fn linux_only_probes_bwrap_and_firecracker() {
        let mut m = HashMap::new();
        m.insert(Backend::Bwrap, outcome_ok("bubblewrap 0.8.0"));
        m.insert(Backend::Firecracker, outcome_ok("Firecracker v1.7.0"));
        let checks = check_with(&host(OsFamily::Linux), &MockProber::new(m)).await;
        assert_eq!(checks.len(), 4);
        let by_label = by_label(&checks);
        assert_eq!(by_label["sandbox bwrap"].status, Status::Ok);
        assert_eq!(by_label["sandbox firecracker"].status, Status::Ok);
        assert_eq!(by_label["sandbox vz"].status, Status::Warn);
        assert_eq!(by_label["sandbox wsl2"].status, Status::Warn);
        // wsl2 is not selected on native Linux, but it is not "unsupported";
        // the message must not claim so (runtime selects bwrap here).
        assert!(
            !by_label["sandbox wsl2"].reason.contains("not supported"),
            "got {}",
            by_label["sandbox wsl2"].reason
        );
    }

    #[tokio::test]
    async fn linux_missing_firecracker_is_warn_not_fail() {
        // firecracker is never auto-selected on Linux (bwrap is); its absence
        // is not a failure, just an unused optional backend (FIR-193).
        let mut m = HashMap::new();
        m.insert(Backend::Bwrap, outcome_ok("bubblewrap 0.9.0"));
        m.insert(
            Backend::Firecracker,
            outcome_err("firecracker --version: No such file"),
        );
        let checks = check_with(&host(OsFamily::Linux), &MockProber::new(m)).await;
        let fc = checks
            .iter()
            .find(|c| c.category == "sandbox firecracker")
            .expect("firecracker check");
        assert_eq!(fc.status, Status::Warn);
    }

    #[tokio::test]
    async fn linux_missing_bwrap_is_fail() {
        let mut m = HashMap::new();
        m.insert(Backend::Bwrap, outcome_err("bwrap: not found in PATH"));
        m.insert(Backend::Firecracker, outcome_ok("Firecracker v1.7.0"));
        let checks = check_with(&host(OsFamily::Linux), &MockProber::new(m)).await;
        let bwrap = checks
            .iter()
            .find(|c| c.category == "sandbox bwrap")
            .expect("bwrap check must be present");
        assert_eq!(bwrap.status, Status::Fail);
        assert!(bwrap.reason.contains("not found in PATH"));
    }

    #[tokio::test]
    async fn macos_reports_vz_warn_and_others_unsupported() {
        let checks = check_with(&host(OsFamily::MacOs), &MockProber::new(HashMap::new())).await;
        let by_label = by_label(&checks);
        assert_eq!(by_label["sandbox vz"].status, Status::Warn);
        assert!(by_label["sandbox vz"].reason.contains("macOS 13+"));
        assert_eq!(by_label["sandbox bwrap"].status, Status::Warn);
        assert_eq!(by_label["sandbox firecracker"].status, Status::Warn);
        assert_eq!(by_label["sandbox wsl2"].status, Status::Warn);
    }

    // -- WSL / userns: verdicts must match `firma run` selection ---------------

    #[tokio::test]
    async fn wsl_bwrap_not_ok_and_wsl2_not_unsupported() {
        // On WSL the runtime refuses bwrap (no unprivileged userns) and
        // auto-selects the wsl2 backend. Doctor must reflect that.
        let mut m = HashMap::new();
        m.insert(Backend::Bwrap, outcome_ok("bubblewrap 0.9.0"));
        let probe = HostProbe {
            os: OsFamily::Linux,
            wsl: true,
            userns_restricted: None,
        };
        let checks = check_with(&probe, &MockProber::new(m)).await;
        let by_label = by_label(&checks);

        // bwrap must NOT be OK even though the binary is present.
        assert_ne!(
            by_label["sandbox bwrap"].status,
            Status::Ok,
            "bwrap must not be OK on WSL: {}",
            by_label["sandbox bwrap"].reason
        );
        assert!(
            by_label["sandbox bwrap"]
                .reason
                .to_lowercase()
                .contains("wsl"),
            "got {}",
            by_label["sandbox bwrap"].reason
        );

        // wsl2 is the selected backend here: not OK-blocked, not "unsupported".
        assert_eq!(by_label["sandbox wsl2"].status, Status::Ok);
        assert!(
            !by_label["sandbox wsl2"].reason.contains("not supported"),
            "got {}",
            by_label["sandbox wsl2"].reason
        );
    }

    #[tokio::test]
    async fn native_linux_userns_restricted_bwrap_fails() {
        // bwrap binary present, but unprivileged userns blocked by sysctl:
        // runtime refuses bwrap at preflight, so doctor must FAIL it.
        let mut m = HashMap::new();
        m.insert(Backend::Bwrap, outcome_ok("bubblewrap 0.9.0"));
        let probe = HostProbe {
            os: OsFamily::Linux,
            wsl: false,
            userns_restricted: Some("/proc/sys/user/max_user_namespaces".to_owned()),
        };
        let checks = check_with(&probe, &MockProber::new(m)).await;
        let bwrap = checks
            .iter()
            .find(|c| c.category == "sandbox bwrap")
            .expect("bwrap check");
        assert_eq!(bwrap.status, Status::Fail);
        assert!(
            bwrap.reason.contains("max_user_namespaces"),
            "got {}",
            bwrap.reason
        );
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
        let checks = check_with(&host(OsFamily::Windows), &MockProber::new(m)).await;
        let wsl2 = checks
            .iter()
            .find(|c| c.category == "sandbox wsl2")
            .expect("wsl2 check must be present");
        assert_eq!(wsl2.status, Status::Ok);
        assert!(wsl2.reason.contains("2.0.0"));
    }
}
