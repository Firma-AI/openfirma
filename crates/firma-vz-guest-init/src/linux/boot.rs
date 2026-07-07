use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use super::error::{InitError, InitResult};
use super::log;

/// Boot-time values passed by the VZ runner on the kernel command line.
#[derive(Debug)]
pub struct BootContract {
    /// Virtiofs tag containing the runtime share exported by the host runner.
    pub virtiofs_tag: String,
    /// Path to the launch contract inside the mounted runtime share.
    pub launch_contract: PathBuf,
    /// Network device mode accepted by this init payload.
    pub network: BootNetworkMode,
}

/// Network shape requested for the guest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootNetworkMode {
    /// No guest network device is attached.
    None,
}

/// Reads `/proc/cmdline` and converts Firma boot arguments into a boot contract.
pub fn parse_boot_contract() -> InitResult<BootContract> {
    let cmdline = fs::read_to_string("/proc/cmdline")
        .map_err(|error| InitError::ReadKernelCmdline { source: error })?;
    log(&format!("cmdline: {}", cmdline.trim()));
    boot_contract_from_cmdline(&cmdline)
}

/// Converts the Linux kernel command line into the init boot contract.
pub fn boot_contract_from_cmdline(cmdline: &str) -> InitResult<BootContract> {
    let args = parse_cmdline(cmdline);
    let Some(virtiofs_tag) = args.get("firma.virtiofs_tag") else {
        return Err(InitError::MissingKernelArg {
            name: "firma.virtiofs_tag",
        });
    };

    let Some(contract_path) = args.get("firma.launch_contract") else {
        return Err(InitError::MissingKernelArg {
            name: "firma.launch_contract",
        });
    };

    let Some(network_mode) = args.get("firma.network") else {
        return Err(InitError::MissingKernelArg {
            name: "firma.network",
        });
    };

    let network = BootNetworkMode::from_kernel_arg(network_mode)?;

    Ok(BootContract {
        virtiofs_tag: virtiofs_tag.clone(),
        launch_contract: PathBuf::from(contract_path),
        network,
    })
}

impl BootNetworkMode {
    /// Parses the supported `firma.network` kernel argument.
    fn from_kernel_arg(mode: &str) -> InitResult<Self> {
        match mode {
            "none" => Ok(Self::None),
            mode => Err(InitError::UnsupportedNetworkMode {
                mode: mode.to_string(),
            }),
        }
    }
}

/// Parses whitespace-delimited `key=value` kernel arguments.
fn parse_cmdline(cmdline: &str) -> BTreeMap<String, String> {
    cmdline
        .split_whitespace()
        .filter_map(|arg| {
            let (key, value) = arg.split_once('=')?;
            Some((key.to_string(), value.to_string()))
        })
        .collect()
}
