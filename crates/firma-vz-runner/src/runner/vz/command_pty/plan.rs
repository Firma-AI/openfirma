use std::num::NonZeroU32;

use crate::runner::{RunnerError, RunnerResult};

/// Accepted command PTY data bridge shape derived from a validated VM plan.
#[derive(Debug, Clone, Copy)]
pub struct CommandPtyBridgePlan {
    data_port: NonZeroU32,
    control_port: NonZeroU32,
}

/// Command PTY and Sidecar ports checked together before accepting the bridge plan.
#[derive(Debug, Clone, Copy)]
pub struct CommandPtyBridgePorts {
    pub data: NonZeroU32,
    pub control: NonZeroU32,
    pub sidecar: NonZeroU32,
}

impl CommandPtyBridgePlan {
    /// Accepts the command PTY data listener after the VSOCK transport shape is known.
    pub fn from_ports(ports: CommandPtyBridgePorts) -> RunnerResult<Self> {
        if ports.data == ports.sidecar {
            return Err(RunnerError::CommandPtyPortConflictsWithSidecar {
                pty_port: ports.data,
                sidecar_port: ports.sidecar.get(),
            });
        }

        if ports.control == ports.sidecar {
            return Err(RunnerError::CommandPtyPortConflictsWithSidecar {
                pty_port: ports.control,
                sidecar_port: ports.sidecar.get(),
            });
        }

        Ok(Self {
            data_port: ports.data,
            control_port: ports.control,
        })
    }

    /// Returns the guest-side VSOCK data port used for command PTY traffic.
    pub const fn data_port(self) -> NonZeroU32 {
        self.data_port
    }

    /// Returns the guest-side VSOCK control port reserved for command PTY control traffic.
    pub const fn control_port(self) -> NonZeroU32 {
        self.control_port
    }
}
