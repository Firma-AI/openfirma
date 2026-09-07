use super::super::RunnerError;
use super::broker_bridge::BrokerBridgePlan;
use super::command_pty::{CommandPtyBridgePlan, CommandPtyBridgePorts};
use super::sidecar_bridge::SidecarBridgePlan;
use crate::vm::{SocketDeviceKind, VmNetworkMode, VmPlan};

/// Accepted VSOCK transport shape used by the Apple VZ runtime.
#[derive(Debug, Clone)]
pub struct VzTransportPlan {
    sidecar: SidecarBridgePlan,
    command_pty: Option<CommandPtyBridgePlan>,
    broker: Option<BrokerBridgePlan>,
    socket_device_count: usize,
}

impl VzTransportPlan {
    /// Returns the accepted Sidecar bridge plan.
    pub const fn sidecar(&self) -> &SidecarBridgePlan {
        &self.sidecar
    }

    /// Returns the accepted command PTY transport plan, when command PTY is enabled.
    pub const fn command_pty(&self) -> Option<&CommandPtyBridgePlan> {
        self.command_pty.as_ref()
    }

    /// Returns the accepted secret broker transport plan, when enabled.
    pub const fn broker(&self) -> Option<&BrokerBridgePlan> {
        self.broker.as_ref()
    }

    /// Returns whether this transport plan includes a command PTY bridge.
    pub const fn command_pty_enabled(&self) -> bool {
        self.command_pty.is_some()
    }

    /// Returns the number of VZ socket devices accepted for this transport.
    pub const fn socket_device_count(&self) -> usize {
        self.socket_device_count
    }
}

impl TryFrom<&VmPlan> for VzTransportPlan {
    type Error = RunnerError;

    /// Accepts the single VSOCK transport device and derives all bridge subplans.
    fn try_from(plan: &VmPlan) -> Result<Self, Self::Error> {
        if plan.network_mode != VmNetworkMode::VsockSidecar {
            return Err(RunnerError::InvalidVsockNetworkMode);
        }

        if plan.socket_devices.len() != 1 {
            return Err(RunnerError::InvalidSocketDeviceCount {
                count: plan.socket_devices.len(),
            });
        }

        let socket_device = &plan.socket_devices[0];
        if socket_device.kind != SocketDeviceKind::VirtioVsockSidecar {
            return Err(RunnerError::InvalidSocketDeviceKind);
        }

        let sidecar = SidecarBridgePlan::from_parts(
            socket_device.sidecar_port,
            socket_device.sidecar_host_addr,
        )?;
        let command_pty = match (plan.pty, socket_device.command_pty) {
            (false, _) => None,
            (true, None) => return Err(RunnerError::CommandPtyMissingPlan),
            (true, Some(command_pty)) => {
                Some(CommandPtyBridgePlan::from_ports(CommandPtyBridgePorts {
                    data: command_pty.data_port,
                    control: command_pty.control_port,
                    sidecar: sidecar.guest_port(),
                })?)
            }
        };
        let broker = plan.broker.as_ref().map(BrokerBridgePlan::from_vm_plan);

        Ok(Self {
            sidecar,
            command_pty,
            broker,
            socket_device_count: plan.socket_devices.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use serde_json::json;

    use super::*;
    use crate::layout::VzGuestLayout;
    use crate::test_utils::{
        VZ_TEST_ROOTFS_SIZE_BYTES, read_contract_without_custody, valid_contract_json,
        vm_plan_fixture,
    };

    #[test]
    fn transport_plan_accepts_vm_plan_socket_device() -> Result<()> {
        let (_temp, plan) = vm_plan_fixture(VZ_TEST_ROOTFS_SIZE_BYTES)?;

        let transport = VzTransportPlan::try_from(&plan)?;

        assert_eq!(
            transport.sidecar().guest_port().get(),
            plan.socket_devices[0].sidecar_port
        );
        assert!(transport.command_pty().is_none());
        assert!(!transport.command_pty_enabled());
        assert_eq!(transport.socket_device_count(), 1);

        Ok(())
    }

    #[test]
    fn transport_plan_accepts_command_pty_subplan() -> Result<()> {
        let (_temp, plan) = pty_vm_plan()?;

        let transport = VzTransportPlan::try_from(&plan)?;
        let command_pty = transport
            .command_pty()
            .ok_or_else(|| anyhow::anyhow!("command PTY bridge plan should be present"))?;

        assert_eq!(command_pty.data_port().get(), 18081);
        assert_eq!(command_pty.control_port().get(), 18082);
        assert!(transport.command_pty_enabled());

        Ok(())
    }

    #[test]
    fn transport_plan_rejects_missing_socket_device() -> Result<()> {
        let (_temp, mut plan) = vm_plan_fixture(VZ_TEST_ROOTFS_SIZE_BYTES)?;
        plan.socket_devices.clear();

        let error = VzTransportPlan::try_from(&plan)
            .err()
            .ok_or_else(|| anyhow::anyhow!("missing socket device should fail"))?;

        assert!(matches!(
            error,
            RunnerError::InvalidSocketDeviceCount { count: 0 }
        ));

        Ok(())
    }

    #[test]
    fn transport_plan_rejects_multiple_socket_devices() -> Result<()> {
        let (_temp, mut plan) = vm_plan_fixture(VZ_TEST_ROOTFS_SIZE_BYTES)?;
        let extra_socket_device = plan.socket_devices[0].clone();
        plan.socket_devices.push(extra_socket_device);

        let error = VzTransportPlan::try_from(&plan)
            .err()
            .ok_or_else(|| anyhow::anyhow!("multiple socket devices should fail"))?;

        assert!(matches!(
            error,
            RunnerError::InvalidSocketDeviceCount { count: 2 }
        ));

        Ok(())
    }

    #[test]
    fn transport_plan_rejects_zero_sidecar_port() -> Result<()> {
        let (_temp, mut plan) = vm_plan_fixture(VZ_TEST_ROOTFS_SIZE_BYTES)?;
        plan.socket_devices[0].sidecar_port = 0;

        let error = VzTransportPlan::try_from(&plan)
            .err()
            .ok_or_else(|| anyhow::anyhow!("zero sidecar port should fail"))?;

        assert!(matches!(error, RunnerError::ZeroSidecarPort));

        Ok(())
    }

    #[test]
    fn transport_plan_rejects_missing_command_pty_subplan() -> Result<()> {
        let (_temp, mut plan) = vm_plan_fixture(VZ_TEST_ROOTFS_SIZE_BYTES)?;
        plan.pty = true;

        let error = VzTransportPlan::try_from(&plan)
            .err()
            .ok_or_else(|| anyhow::anyhow!("missing command PTY plan should fail"))?;

        assert!(matches!(error, RunnerError::CommandPtyMissingPlan));

        Ok(())
    }

    #[test]
    fn transport_plan_rejects_command_pty_sidecar_port_reuse() -> Result<()> {
        let (_temp, mut plan) = pty_vm_plan()?;
        let pty_port = plan
            .socket_devices
            .first()
            .and_then(|socket_device| socket_device.command_pty)
            .ok_or_else(|| anyhow::anyhow!("command PTY subplan should exist"))?
            .data_port;
        plan.socket_devices[0].sidecar_port = pty_port.get();

        let error = VzTransportPlan::try_from(&plan)
            .err()
            .ok_or_else(|| anyhow::anyhow!("Sidecar port reuse should fail"))?;

        assert!(matches!(
            error,
            RunnerError::CommandPtyPortConflictsWithSidecar {
                pty_port: actual_pty_port,
                sidecar_port,
            } if actual_pty_port == pty_port && sidecar_port == pty_port.get()
        ));

        Ok(())
    }

    fn pty_vm_plan() -> Result<(tempfile::TempDir, VmPlan)> {
        let temp = tempfile::tempdir()?;
        let runtime_dir = temp.path().join("runtime");
        let contract_path = VzGuestLayout::from_runtime_dir(&runtime_dir).launch_contract();
        let mut json = valid_contract_json(temp.path())?;
        json["terminal"]["interactive"] = json!(true);
        json["terminal"]["pty"] = json!(true);
        json["terminal"]["pty_vsock_port"] = json!(18081);
        json["terminal"]["pty_control_vsock_port"] = json!(18082);
        json["terminal"]["term"] = json!("xterm-256color");
        let contract_dir = contract_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("contract path should have parent"))?;
        std::fs::create_dir_all(contract_dir)?;
        std::fs::write(&contract_path, serde_json::to_vec(&json)?)?;
        let contract = read_contract_without_custody(&contract_path)?;
        let plan = VmPlan::from_contract(&contract)?;

        Ok((temp, plan))
    }
}
