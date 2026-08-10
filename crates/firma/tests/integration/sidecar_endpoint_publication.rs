//! Black-box coverage for the Sidecar's child-published TCP readiness contract.

#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "test code: panics are acceptable test failures"
)]

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use p256::pkcs8::{EncodePrivateKey as _, LineEnding};
use wait_timeout::ChildExt as _;

use super::CONFIG_FILE_NAME;

#[derive(serde::Deserialize)]
struct StartupReport {
    protocol_version: u32,
    tcp_listen_addr: SocketAddr,
}

struct RunningSidecar(Child);

impl RunningSidecar {
    fn wait_for_exit(&mut self) -> anyhow::Result<std::process::ExitStatus> {
        self.0
            .wait_timeout(Duration::from_secs(10))?
            .ok_or_else(|| anyhow::anyhow!("Sidecar did not exit within 10 seconds"))
    }
}

impl Drop for RunningSidecar {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn http_proxy_port_zero_publishes_nonzero_effective_endpoint() -> anyhow::Result<()> {
    assert_dynamic_publication("http_proxy")
}

#[test]
fn grpc_port_zero_publishes_nonzero_effective_endpoint() -> anyhow::Result<()> {
    assert_dynamic_publication("grpc")
}

#[test]
fn bind_failure_does_not_publish_an_endpoint() -> anyhow::Result<()> {
    let occupied = TcpListener::bind("127.0.0.1:0")?;
    let fixture = SidecarFixture::new("http_proxy", occupied.local_addr()?)?;
    let mut sidecar = fixture.spawn()?;

    let status = sidecar.wait_for_exit()?;

    assert!(!status.success());
    assert!(!fixture.startup_report_path.exists());
    Ok(())
}

#[cfg(unix)]
#[test]
fn non_tcp_endpoint_does_not_publish_an_endpoint() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let socket_path = root.path().join("sidecar.sock");
    let fixture = SidecarFixture::new_unix(root, &socket_path)?;
    let mut sidecar = fixture.spawn()?;

    let status = sidecar.wait_for_exit()?;

    assert!(!status.success());
    assert!(!fixture.startup_report_path.exists());
    Ok(())
}

fn assert_dynamic_publication(mode: &str) -> anyhow::Result<()> {
    let requested: SocketAddr = "127.0.0.1:0".parse()?;
    let fixture = SidecarFixture::new(mode, requested)?;
    let mut sidecar = fixture.spawn()?;

    let published = wait_for_publication(&mut sidecar.0, &fixture.startup_report_path)?;

    assert_eq!(published.ip(), requested.ip());
    assert_ne!(published.port(), 0);
    TcpStream::connect(published)?;
    Ok(())
}

fn wait_for_publication(child: &mut Child, path: &Path) -> anyhow::Result<SocketAddr> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match std::fs::read_to_string(path) {
            Ok(contents) => {
                let report: StartupReport = toml::from_str(&contents)?;
                assert_eq!(report.protocol_version, 1);
                return Ok(report.tcp_listen_addr);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        if let Some(status) = child.try_wait()? {
            anyhow::bail!("Sidecar exited before endpoint publication: {status}");
        }
        if Instant::now() >= deadline {
            anyhow::bail!(
                "timed out waiting for endpoint publication at {}",
                path.display()
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

struct SidecarFixture {
    _root: tempfile::TempDir,
    config_path: PathBuf,
    startup_report_path: PathBuf,
}

impl SidecarFixture {
    fn new(mode: &str, listen_addr: SocketAddr) -> anyhow::Result<Self> {
        let root = tempfile::tempdir()?;
        let interceptor = format!("mode = \"{mode}\"\nlisten_addr = \"{listen_addr}\"");
        Self::write(root, &interceptor)
    }

    #[cfg(unix)]
    fn new_unix(root: tempfile::TempDir, socket_path: &Path) -> anyhow::Result<Self> {
        let interceptor = format!(
            "mode = \"unix_socket\"\nsocket_path = '{}'",
            socket_path.display()
        );
        Self::write(root, &interceptor)
    }

    fn write(root: tempfile::TempDir, interceptor: &str) -> anyhow::Result<Self> {
        let policy_dir = root.path().join("policies");
        std::fs::create_dir_all(&policy_dir)?;
        std::fs::write(
            policy_dir.join("default.cedar"),
            "permit(principal, action, resource);",
        )?;
        let mapping_path = root.path().join("mapping-rules.toml");
        std::fs::write(
            &mapping_path,
            "[[rules]]\nmethod = \"GET\"\nhost = \"example.test\"\npath = \"*\"\naction_class = \"communication.external.send\"\n",
        )?;
        let audit_key_path = root.path().join("audit.key");
        let audit_key = p256::ecdsa::SigningKey::from_slice(&[7; 32])?;
        std::fs::write(
            &audit_key_path,
            audit_key.to_pkcs8_pem(LineEnding::LF)?.as_bytes(),
        )?;
        let ca_dir = root.path().join("ca");
        let config_path = root.path().join(CONFIG_FILE_NAME);
        std::fs::write(
            &config_path,
            format!(
                "[sidecar.interceptor]\n{interceptor}\n\
                 [sidecar.policy]\ndir = '{}'\n\
                 [sidecar.ca]\ndir = '{}'\n\
                 [sidecar.mapping]\nrules_path = '{}'\ndefault_protected = true\n\
                 [sidecar.audit]\nsink = \"stdout\"\nsigning_key_path = '{}'\n",
                policy_dir.display(),
                ca_dir.display(),
                mapping_path.display(),
                audit_key_path.display(),
            ),
        )?;
        let startup_report_path = root.path().join("sidecar.startup.toml");
        Ok(Self {
            _root: root,
            config_path,
            startup_report_path,
        })
    }

    fn spawn(&self) -> anyhow::Result<RunningSidecar> {
        let child = Command::new(env!("CARGO_BIN_EXE_firma"))
            .args(["sidecar", "--config"])
            .arg(&self.config_path)
            .args(["--health-bind-addr", "127.0.0.1:0"])
            .arg("--startup-report")
            .arg(&self.startup_report_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        Ok(RunningSidecar(child))
    }
}
