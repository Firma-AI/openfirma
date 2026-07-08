use std::collections::BTreeMap;
use std::fs;
use std::net::{AddrParseError, SocketAddr};
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::error::{InitError, InitResult};
use super::log;

const SECRET_ENV_KEYS: &[&str] = &["FIRMA_CAPABILITY_TOKEN"];

/// Raw launch contract shape read from the runtime share.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchContract {
    /// Contract schema version.
    pub version: u32,
    /// Host sandbox id carried for diagnostics and host-side correlation.
    #[serde(default)]
    pub sandbox_id: Option<String>,
    /// Host runtime directory. Guest init uses the mounted guest path instead.
    #[serde(default)]
    pub runtime_dir: Option<PathBuf>,
    /// Host runner binary used to launch the VM.
    #[serde(default)]
    pub runner: Option<RunnerContract>,
    /// Host-provided guest artifact paths.
    #[serde(default)]
    pub guest: Option<GuestContract>,
    /// Command payload to run inside the guest.
    pub command: CommandContract,
    /// Terminal mode requested by the host runner.
    pub terminal: TerminalContract,
    /// Guest mount targets requested by the host runner.
    pub mounts: Vec<MountContract>,
    /// Guest-side network envelope requested by the host runner.
    pub network: NetworkContract,
    /// Required host invariants recorded in the launch contract.
    #[serde(default)]
    pub invariants: Vec<InvariantContract>,
}

/// Host runner metadata carried by the launch contract.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerContract {
    /// Host path to the runner binary that launched the VM.
    pub path: PathBuf,
}

/// Host guest artifact metadata carried by the launch contract.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestContract {
    /// Host path to the Linux kernel image.
    pub kernel: PathBuf,
    /// Host path to the initrd image.
    pub initrd: PathBuf,
    /// Host path to the rootfs image.
    pub rootfs: PathBuf,
}

/// Host invariant metadata carried by the launch contract.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvariantContract {
    /// Invariant name.
    pub name: String,
    /// Invariant enforcement mode.
    pub mode: String,
}

/// Launch contract that has passed guest-side validation.
#[derive(Debug)]
pub struct Contract {
    command: CommandContract,
    terminal: Terminal,
    mounts: Vec<MountContract>,
    network: Network,
}

impl Contract {
    /// Returns the accepted command payload.
    pub fn command(&self) -> &CommandContract {
        &self.command
    }

    /// Returns the accepted mount targets.
    pub fn mounts(&self) -> &[MountContract] {
        &self.mounts
    }

    /// Returns the accepted guest network envelope.
    pub fn network(&self) -> &Network {
        &self.network
    }

    /// Returns the accepted terminal mode.
    pub fn terminal(&self) -> Terminal {
        self.terminal
    }
}

impl TryFrom<LaunchContract> for Contract {
    type Error = InitError;

    /// Accepts a parsed launch contract after guest-side validation.
    fn try_from(contract: LaunchContract) -> Result<Self, Self::Error> {
        validate_contract(&contract)?;
        let terminal = accept_terminal_contract(&contract.terminal)?;
        let network = accept_network_contract(&contract.network)?;

        Ok(Self {
            command: contract.command,
            terminal,
            mounts: contract.mounts,
            network,
        })
    }
}

/// Terminal mode accepted for this guest init stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Terminal {
    /// Noninteractive command execution without a guest PTY bridge.
    NonInteractive,
}

impl Terminal {
    /// Returns the stable terminal mode label used in guest diagnostics.
    pub const fn mode(self) -> &'static str {
        match self {
            Self::NonInteractive => "noninteractive",
        }
    }

    /// Returns whether the accepted command requires interactive terminal handling.
    pub const fn interactive(self) -> bool {
        match self {
            Self::NonInteractive => false,
        }
    }

    /// Returns whether the accepted command requires a guest PTY bridge.
    pub const fn pty(self) -> bool {
        match self {
            Self::NonInteractive => false,
        }
    }
}

/// Command payload from the launch contract.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandContract {
    /// Executable path or name to run.
    pub executable: String,
    /// Arguments passed to the executable.
    pub args: Vec<String>,
    /// Working directory created and selected before process spawn.
    pub cwd: PathBuf,
    /// Complete guest process environment.
    pub env: BTreeMap<String, String>,
    /// Host identity mode recorded by firma-run.
    #[serde(default)]
    pub identity_mode: Option<String>,
}

/// Terminal mode requested by the launch contract.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalContract {
    /// Whether the launched command is expected to be interactive.
    pub interactive: bool,
    /// Whether the command should run behind a guest PTY bridge.
    pub pty: bool,
    /// Optional host VSOCK port used for the command PTY data stream.
    pub pty_vsock_port: Option<u32>,
    /// Optional host VSOCK port used for command PTY control messages.
    pub pty_control_vsock_port: Option<u32>,
    /// Optional terminal type exported to the guest command.
    pub term: Option<String>,
    /// Optional terminal row count.
    pub rows: Option<u16>,
    /// Optional terminal column count.
    pub cols: Option<u16>,
}

/// Mount target requested by the launch contract.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MountContract {
    /// Host source path for the corresponding indexed virtiofs share.
    #[serde(default)]
    pub source: Option<PathBuf>,
    /// Guest path where the indexed virtiofs share should be bind-mounted.
    pub target: PathBuf,
    /// Whether the bind mount should be remounted read-only.
    pub read_only: bool,
}

/// Guest network envelope from the launch contract.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkContract {
    /// Network mode the guest init understands.
    pub mode: NetworkMode,
    /// Guest-local HTTP proxy socket address.
    pub guest_http_proxy_addr: String,
    /// Guest-local DNS stub socket address.
    pub guest_dns_stub_addr: String,
    /// Guest VSOCK port used to reach the host Sidecar bridge.
    pub vsock_sidecar_port: u32,
    /// Host-side Sidecar socket address reached by the runner bridge.
    pub sidecar_host_addr: String,
    /// Whether direct guest network devices are allowed.
    pub direct_network_devices_allowed: bool,
    /// DNS confinement mode the guest init understands.
    pub dns_mode: DnsMode,
    /// Attribution headers the guest proxy should add when absent.
    pub attribution_headers: BTreeMap<String, String>,
}

/// Guest network envelope accepted for this init stage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Network {
    mode: NetworkMode,
    guest_http_proxy_addr: SocketAddr,
    guest_dns_stub_addr: SocketAddr,
    vsock_sidecar_port: NonZeroU32,
    sidecar_host_addr: SocketAddr,
    dns_mode: DnsMode,
    attribution_headers: BTreeMap<String, String>,
}

impl Network {
    /// Returns the accepted guest network mode.
    pub const fn mode(&self) -> NetworkMode {
        self.mode
    }

    /// Returns the accepted guest DNS mode.
    pub const fn dns_mode(&self) -> DnsMode {
        self.dns_mode
    }

    /// Returns the guest-local HTTP proxy socket address.
    pub const fn guest_http_proxy_addr(&self) -> SocketAddr {
        self.guest_http_proxy_addr
    }

    /// Returns the guest-local DNS stub socket address.
    pub const fn guest_dns_stub_addr(&self) -> SocketAddr {
        self.guest_dns_stub_addr
    }

    /// Returns the VSOCK port used to reach the host Sidecar bridge.
    pub const fn vsock_sidecar_port(&self) -> NonZeroU32 {
        self.vsock_sidecar_port
    }

    /// Returns the host-side Sidecar address consumed by the host VSOCK bridge.
    pub const fn sidecar_host_addr(&self) -> SocketAddr {
        self.sidecar_host_addr
    }

    /// Returns the attribution headers accepted for guest proxy injection.
    pub fn attribution_headers(&self) -> &BTreeMap<String, String> {
        &self.attribution_headers
    }
}

/// Network mode supported by the current guest init.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    /// Guest egress is expected to flow through a VSOCK Sidecar bridge.
    VsockSidecar,
}

/// DNS mode supported by the current guest init.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DnsMode {
    /// Guest DNS is expected to use a confined local stub.
    ConfinedStub,
}

/// Reads and parses a launch contract without accepting it for execution.
pub fn read_contract(contract_path: &Path) -> InitResult<LaunchContract> {
    let metadata = fs::metadata(contract_path).map_err(|error| InitError::ContractNotVisible {
        path: contract_path.to_path_buf(),
        source: error,
    })?;

    if !metadata.is_file() {
        return Err(InitError::ContractNotRegularFile {
            path: contract_path.to_path_buf(),
        });
    }

    log(&format!(
        "contract visible at {} ({} bytes)",
        contract_path.display(),
        metadata.len()
    ));

    let json = fs::read(contract_path).map_err(|error| InitError::ReadContract {
        path: contract_path.to_path_buf(),
        source: error,
    })?;

    serde_json::from_slice(&json).map_err(|error| InitError::ParseContract {
        path: contract_path.to_path_buf(),
        source: error,
    })
}

/// Reads, validates, and accepts a launch contract for execution.
pub fn accept_contract(contract_path: &Path) -> InitResult<Contract> {
    read_contract(contract_path)?.try_into()
}

/// Validates contract schema semantics before guest execution can start.
pub fn validate_contract(contract: &LaunchContract) -> InitResult<()> {
    validate_contract_header(contract)?;
    let _terminal = accept_terminal_contract(&contract.terminal)?;
    let _network = accept_network_contract(&contract.network)?;

    Ok(())
}

/// Validates top-level contract fields before accepting substructures.
fn validate_contract_header(contract: &LaunchContract) -> InitResult<()> {
    observe_host_launch_metadata(contract);

    if contract.version != 1 {
        return Err(InitError::InvalidContractVersion {
            version: contract.version,
        });
    }

    if contract.command.executable.trim().is_empty() {
        return Err(InitError::EmptyExecutable);
    }

    if !contract.command.cwd.is_absolute() {
        return Err(InitError::RelativeCommandCwd {
            path: contract.command.cwd.clone(),
        });
    }

    for key in SECRET_ENV_KEYS {
        if contract.command.env.contains_key(*key) {
            return Err(InitError::SecretEnvKey { key });
        }
    }

    for mount in &contract.mounts {
        if !mount.target.is_absolute() {
            return Err(InitError::RelativeMountTarget {
                path: mount.target.clone(),
            });
        }
    }

    Ok(())
}

/// Marks host-owned launch metadata as intentionally parsed but not executed.
fn observe_host_launch_metadata(contract: &LaunchContract) {
    let _ = (
        &contract.sandbox_id,
        &contract.runtime_dir,
        &contract.invariants,
        &contract.command.identity_mode,
    );

    if let Some(runner) = &contract.runner {
        let _ = &runner.path;
    }

    if let Some(guest) = &contract.guest {
        let _ = (&guest.kernel, &guest.initrd, &guest.rootfs);
    }

    for invariant in &contract.invariants {
        let _ = (&invariant.name, &invariant.mode);
    }

    for mount in &contract.mounts {
        let _ = &mount.source;
    }
}

/// Accepts terminal metadata into the executable guest shape.
fn accept_terminal_contract(terminal: &TerminalContract) -> InitResult<Terminal> {
    if terminal.pty {
        return Err(InitError::UnsupportedTerminalPty);
    }

    if terminal.interactive {
        return Err(InitError::UnsupportedTerminalInteractive);
    }

    if terminal.pty_vsock_port.is_some() {
        return Err(InitError::TerminalPtyPortWithoutPty {
            field: "terminal.pty_vsock_port",
        });
    }

    if terminal.pty_control_vsock_port.is_some() {
        return Err(InitError::TerminalPtyPortWithoutPty {
            field: "terminal.pty_control_vsock_port",
        });
    }

    if let Some(term) = &terminal.term
        && term.trim().is_empty()
    {
        return Err(InitError::EmptyTerminalTerm);
    }

    if terminal.rows.is_some_and(|rows| rows == 0) {
        return Err(InitError::ZeroTerminalDimension {
            field: "terminal.rows",
        });
    }

    if terminal.cols.is_some_and(|cols| cols == 0) {
        return Err(InitError::ZeroTerminalDimension {
            field: "terminal.cols",
        });
    }

    Ok(Terminal::NonInteractive)
}

/// Accepts the guest network envelope into parsed addresses and ports.
fn accept_network_contract(network: &NetworkContract) -> InitResult<Network> {
    match network.mode {
        NetworkMode::VsockSidecar => {}
    }

    match network.dns_mode {
        DnsMode::ConfinedStub => {}
    }

    let guest_http_proxy_addr = require_loopback_socket_addr(
        "network.guest_http_proxy_addr",
        &network.guest_http_proxy_addr,
    )?;

    let guest_dns_stub_addr =
        require_loopback_socket_addr("network.guest_dns_stub_addr", &network.guest_dns_stub_addr)?;
    let sidecar_host_addr =
        require_loopback_socket_addr("network.sidecar_host_addr", &network.sidecar_host_addr)?;

    let vsock_sidecar_port =
        NonZeroU32::new(network.vsock_sidecar_port).ok_or(InitError::ZeroNetworkPort {
            field: "network.vsock_sidecar_port",
        })?;

    if network.direct_network_devices_allowed {
        return Err(InitError::DirectNetworkDevicesAllowed);
    }

    for (name, value) in &network.attribution_headers {
        if name.trim().is_empty() {
            return Err(InitError::EmptyAttributionHeaderName);
        }

        if value.trim().is_empty() {
            return Err(InitError::EmptyAttributionHeaderValue { name: name.clone() });
        }
    }

    Ok(Network {
        mode: network.mode,
        guest_http_proxy_addr,
        guest_dns_stub_addr,
        vsock_sidecar_port,
        sidecar_host_addr,
        dns_mode: network.dns_mode,
        attribution_headers: network.attribution_headers.clone(),
    })
}

/// Parses and requires a loopback socket address.
fn require_loopback_socket_addr(field: &'static str, value: &str) -> InitResult<SocketAddr> {
    let addr = value
        .parse::<SocketAddr>()
        .map_err(
            |source: AddrParseError| InitError::InvalidNetworkSocketAddr {
                field,
                value: value.to_string(),
                source,
            },
        )?;

    if !addr.ip().is_loopback() {
        return Err(InitError::NonLoopbackNetworkSocketAddr {
            field,
            value: value.to_string(),
        });
    }

    if addr.port() == 0 {
        return Err(InitError::ZeroNetworkPort { field });
    }

    Ok(addr)
}
