use std::collections::BTreeMap;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(unix)]
use std::io;
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
#[cfg(unix)]
use std::sync::mpsc;
#[cfg(unix)]
use std::thread::{self, JoinHandle};

use crate::backend::SandboxHandle;
use crate::config::SidecarEndpoint;
use crate::error::RunError;

const STRUCTURAL_PROXY_LISTEN_ADDR: &str = "127.0.0.1:18080";

/// Runtime-side network artifacts that must live while the wrapped process runs.
pub struct NetworkRuntime {
    env_overrides: BTreeMap<String, String>,
    #[cfg(unix)]
    _adapter: Option<SidecarAdapter>,
}

impl NetworkRuntime {
    /// Returns environment values to merge into wrapped process launch env.
    #[must_use]
    pub fn env_overrides(&self) -> &BTreeMap<String, String> {
        &self.env_overrides
    }
}

/// Prepare network runtime artifacts for a sandbox launch.
///
/// # Errors
///
/// Returns an error when fail-closed endpoint checks fail, when helper
/// sockets cannot be created, or when current executable path resolution fails.
pub fn prepare_network_runtime(
    handle: &SandboxHandle,
    sidecar_endpoint: &SidecarEndpoint,
) -> Result<NetworkRuntime, RunError> {
    if handle.network_policy.fail_closed {
        ensure_sidecar_reachable(sidecar_endpoint)?;
    }

    if !handle.network_policy.enforce_network_namespace {
        return Ok(NetworkRuntime {
            env_overrides: BTreeMap::new(),
            #[cfg(unix)]
            _adapter: None,
        });
    }

    #[cfg(not(unix))]
    {
        let _ = sidecar_endpoint;
        return Err(RunError::UnsupportedBackend {
            backend: handle.backend.to_string(),
            reason: "structural network confinement currently requires unix sockets".to_string(),
        });
    }

    #[cfg(unix)]
    {
        let adapter_path = handle.runtime_dir.join("sidecar-upstream.sock");
        let adapter = SidecarAdapter::start(&adapter_path, sidecar_endpoint)?;
        let current_exe = std::env::current_exe().map_err(|error| {
            RunError::Internal(format!(
                "failed to resolve current executable path: {error}"
            ))
        })?;

        let mut env_overrides = BTreeMap::new();
        env_overrides.insert(
            "HTTP_PROXY".to_string(),
            format!("http://{STRUCTURAL_PROXY_LISTEN_ADDR}"),
        );
        env_overrides.insert(
            "HTTPS_PROXY".to_string(),
            format!("http://{STRUCTURAL_PROXY_LISTEN_ADDR}"),
        );
        env_overrides.insert(
            "http_proxy".to_string(),
            format!("http://{STRUCTURAL_PROXY_LISTEN_ADDR}"),
        );
        env_overrides.insert(
            "https_proxy".to_string(),
            format!("http://{STRUCTURAL_PROXY_LISTEN_ADDR}"),
        );
        env_overrides.insert(
            "ALL_PROXY".to_string(),
            format!("http://{STRUCTURAL_PROXY_LISTEN_ADDR}"),
        );
        env_overrides.insert(
            "all_proxy".to_string(),
            format!("http://{STRUCTURAL_PROXY_LISTEN_ADDR}"),
        );
        env_overrides.insert(
            "FIRMA_RUN_PROXY_LISTEN_ADDR".to_string(),
            STRUCTURAL_PROXY_LISTEN_ADDR.to_string(),
        );
        env_overrides.insert(
            "FIRMA_RUN_PROXY_BRIDGE_UPSTREAM_UDS".to_string(),
            adapter_path.display().to_string(),
        );
        env_overrides.insert(
            "FIRMA_RUN_SELF_EXE".to_string(),
            current_exe.display().to_string(),
        );

        Ok(NetworkRuntime {
            env_overrides,
            _adapter: Some(adapter),
        })
    }
}

fn ensure_sidecar_reachable(endpoint: &SidecarEndpoint) -> Result<(), RunError> {
    match endpoint {
        SidecarEndpoint::Tcp { addr } => {
            TcpStream::connect_timeout(addr, Duration::from_millis(500)).map_err(|error| {
                RunError::Backend {
                    backend: "sidecar".to_string(),
                    reason: format!("sidecar endpoint {addr} is unreachable: {error}"),
                }
            })?;
            Ok(())
        }
        SidecarEndpoint::Unix { path } => ensure_unix_endpoint_reachable(path),
    }
}

fn ensure_unix_endpoint_reachable(path: &Path) -> Result<(), RunError> {
    #[cfg(unix)]
    {
        UnixStream::connect(path).map_err(|error| RunError::Backend {
            backend: "sidecar".to_string(),
            reason: format!(
                "sidecar unix socket {} is unreachable: {error}",
                path.display()
            ),
        })?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        let _ = path;
        Err(RunError::UnsupportedBackend {
            backend: "sidecar".to_string(),
            reason: "unix socket sidecar endpoints are unsupported on this host".to_string(),
        })
    }
}

#[cfg(unix)]
struct SidecarAdapter {
    socket_path: PathBuf,
    stop_tx: Option<mpsc::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

#[cfg(unix)]
impl SidecarAdapter {
    fn start(socket_path: &Path, upstream: &SidecarEndpoint) -> Result<Self, RunError> {
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| RunError::Backend {
                backend: "sidecar_adapter".to_string(),
                reason: format!(
                    "failed to create adapter socket dir {}: {error}",
                    parent.display()
                ),
            })?;
        }

        let _ = std::fs::remove_file(socket_path);
        let listener = UnixListener::bind(socket_path).map_err(|error| RunError::Backend {
            backend: "sidecar_adapter".to_string(),
            reason: format!(
                "failed to bind adapter socket {}: {error}",
                socket_path.display()
            ),
        })?;
        listener
            .set_nonblocking(true)
            .map_err(|error| RunError::Backend {
                backend: "sidecar_adapter".to_string(),
                reason: format!("failed to set adapter listener non-blocking: {error}"),
            })?;

        let (stop_tx, stop_rx) = mpsc::channel::<()>();
        let socket_for_task = socket_path.to_path_buf();
        let upstream_for_task = upstream.clone();

        let task = thread::Builder::new()
            .name("firma-run-sidecar-adapter".to_string())
            .spawn(move || {
                loop {
                    if stop_rx.try_recv().is_ok() {
                        break;
                    }

                    match listener.accept() {
                        Ok((client, _)) => {
                            let upstream_target = upstream_for_task.clone();
                            thread::spawn(move || {
                                if let Err(error) = relay_to_sidecar(client, &upstream_target) {
                                    tracing::warn!("sidecar adapter relay failed: {error}");
                                }
                            });
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(25));
                        }
                        Err(error) => {
                            tracing::warn!("sidecar adapter accept failed: {error}");
                            thread::sleep(Duration::from_millis(50));
                        }
                    }
                }
            })
            .map_err(|error| RunError::Backend {
                backend: "sidecar_adapter".to_string(),
                reason: format!("failed to spawn adapter task: {error}"),
            })?;

        Ok(Self {
            socket_path: socket_for_task,
            stop_tx: Some(stop_tx),
            task: Some(task),
        })
    }
}

#[cfg(unix)]
impl Drop for SidecarAdapter {
    fn drop(&mut self) {
        if let Some(stop_tx) = self.stop_tx.take() {
            let _ = stop_tx.send(());
        }

        if let Some(task) = self.task.take() {
            let _ = task.join();
        }

        let _ = std::fs::remove_file(&self.socket_path);
    }
}

#[cfg(unix)]
fn relay_to_sidecar(mut client: UnixStream, upstream: &SidecarEndpoint) -> io::Result<()> {
    match upstream {
        SidecarEndpoint::Tcp { addr } => {
            let mut target = TcpStream::connect_timeout(addr, Duration::from_secs(1))?;
            relay_unix_to_tcp(&mut client, &mut target)
        }
        SidecarEndpoint::Unix { path } => {
            let mut target = UnixStream::connect(path)?;
            relay_unix_to_unix(&mut client, &mut target)
        }
    }
}

#[cfg(unix)]
fn relay_unix_to_tcp(client: &mut UnixStream, target: &mut TcpStream) -> io::Result<()> {
    let mut client_read = client.try_clone()?;
    let mut client_write = client.try_clone()?;
    let mut target_read = target.try_clone()?;
    let mut target_write = target.try_clone()?;

    let c_to_t = thread::spawn(move || io::copy(&mut client_read, &mut target_write));
    let t_to_c = thread::spawn(move || io::copy(&mut target_read, &mut client_write));

    c_to_t
        .join()
        .map_err(|_| io::Error::other("relay panic"))??;
    t_to_c
        .join()
        .map_err(|_| io::Error::other("relay panic"))??;
    Ok(())
}

#[cfg(unix)]
fn relay_unix_to_unix(client: &mut UnixStream, target: &mut UnixStream) -> io::Result<()> {
    let mut client_read = client.try_clone()?;
    let mut client_write = client.try_clone()?;
    let mut target_read = target.try_clone()?;
    let mut target_write = target.try_clone()?;

    let c_to_t = thread::spawn(move || io::copy(&mut client_read, &mut target_write));
    let t_to_c = thread::spawn(move || io::copy(&mut target_read, &mut client_write));

    c_to_t
        .join()
        .map_err(|_| io::Error::other("relay panic"))??;
    t_to_c
        .join()
        .map_err(|_| io::Error::other("relay panic"))??;
    Ok(())
}
