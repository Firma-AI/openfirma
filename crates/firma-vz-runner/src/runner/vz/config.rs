use std::os::fd::{IntoRawFd, OwnedFd};
use std::path::Path;

use objc2::{AnyThread, rc::Retained};
use objc2_foundation::{NSArray, NSDictionary, NSError, NSFileHandle, NSString, NSUInteger, NSURL};
use objc2_virtualization::{
    VZConsoleDeviceConfiguration, VZDiskImageCachingMode, VZDiskImageStorageDeviceAttachment,
    VZDiskImageSynchronizationMode, VZEntropyDeviceConfiguration, VZFileHandleSerialPortAttachment,
    VZGenericMachineIdentifier, VZGenericPlatformConfiguration, VZLinuxBootLoader,
    VZMultipleDirectoryShare, VZSharedDirectory, VZStorageDeviceConfiguration,
    VZVirtioBlockDeviceConfiguration, VZVirtioConsoleDeviceConfiguration,
    VZVirtioConsolePortConfiguration, VZVirtioEntropyDeviceConfiguration,
    VZVirtioFileSystemDeviceConfiguration, VZVirtualMachine, VZVirtualMachineConfiguration,
};

use super::super::{RunnerError, RunnerResult};
use super::sidecar_bridge::configure_socket_devices;
use super::transport::VzTransportPlan;
use crate::vm::{FIRMA_VIRTIOFS_TAG, VmPlan};

// We keep the default VM small and predictable for the local runner path. Two
// vCPUs are enough for guest init, helper services and one foreground command
// without taking an aggressive piece of the developer's host.
const DEFAULT_CPU_COUNT: NSUInteger = 2;

// The guest image currently carries init, shell tooling and smoke-test
// utilities. 2 GiB leaves practical headroom for that stack while staying low
// enough to run comfortably on laptops. This is a runner default, not a policy
// boundary. make it explicit configuration when workload sizing becomes part of
// the launch contract.
const DEFAULT_MEMORY_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Host-side VZ state that has passed validation and can be started.
pub struct Vz {
    pub config: Retained<VZVirtualMachineConfiguration>,
    pub transport: VzTransportPlan,
}

impl Vz {
    /// Builds the accepted VZ configuration boundary from a VM plan.
    pub fn from_plan(
        plan: &VmPlan,
        transport: VzTransportPlan,
        vm_reads_from: OwnedFd,
        vm_writes_to: OwnedFd,
    ) -> RunnerResult<Self> {
        Ok(Self {
            config: create_vm_configuration(plan, &transport, vm_reads_from, vm_writes_to)?,
            transport,
        })
    }
}

/// Creates and validates the host-side Apple VZ machine configuration.
fn create_vm_configuration(
    plan: &VmPlan,
    transport: &VzTransportPlan,
    vm_reads_from: OwnedFd,
    vm_writes_to: OwnedFd,
) -> RunnerResult<Retained<VZVirtualMachineConfiguration>> {
    let config = unsafe {
        if !VZVirtualMachine::isSupported() {
            return Err(RunnerError::VirtualizationUnsupported);
        }

        let config = VZVirtualMachineConfiguration::new();
        let platform = VZGenericPlatformConfiguration::new();
        let machine_identifier =
            VZGenericMachineIdentifier::init(VZGenericMachineIdentifier::alloc());
        platform.setMachineIdentifier(&machine_identifier);
        config.setPlatform(&platform);

        let boot_loader = create_linux_boot_loader(plan)?;
        config.setBootLoader(Some(&boot_loader));

        config.setCPUCount(clamped_cpu_count());
        config.setMemorySize(clamped_memory_size());
        configure_entropy(&config);
        configure_rootfs_storage(&config, &plan.rootfs)?;
        configure_directory_shares(&config, plan)?;
        configure_socket_devices(&config, transport.sidecar());
        configure_console_stdio(&config, vm_reads_from, vm_writes_to);

        config
            .validateWithError()
            .map_err(|error| RunnerError::ConfigurationValidation {
                reason: ns_error_message(&error),
            })?;

        config
    };

    Ok(config)
}

/// Builds the Linux bootloader with the planned kernel, initrd and command line.
fn create_linux_boot_loader(plan: &VmPlan) -> RunnerResult<Retained<VZLinuxBootLoader>> {
    let kernel_url = nsurl_from_path(&plan.kernel)?;
    let initrd_url = nsurl_from_path(&plan.initrd)?;
    let boot_loader =
        unsafe { VZLinuxBootLoader::initWithKernelURL(VZLinuxBootLoader::alloc(), &kernel_url) };
    unsafe {
        boot_loader.setInitialRamdiskURL(Some(&initrd_url));
        boot_loader.setCommandLine(&NSString::from_str(&plan.kernel_command_line));
    }

    Ok(boot_loader)
}

/// Adds the virtio entropy device required by the guest.
fn configure_entropy(config: &VZVirtualMachineConfiguration) {
    let entropy_device = unsafe { VZVirtioEntropyDeviceConfiguration::new() };
    let entropy_devices: Retained<NSArray<VZEntropyDeviceConfiguration>> =
        NSArray::from_retained_slice(&[Retained::into_super(entropy_device)]);

    unsafe {
        config.setEntropyDevices(&entropy_devices);
    }
}

/// Attaches the rootfs image as the guest's virtio block device.
fn configure_rootfs_storage(
    config: &VZVirtualMachineConfiguration,
    rootfs: &Path,
) -> RunnerResult<()> {
    let rootfs_url = nsurl_from_path(rootfs)?;
    let disk_attachment = unsafe {
        VZDiskImageStorageDeviceAttachment::initWithURL_readOnly_cachingMode_synchronizationMode_error(
            VZDiskImageStorageDeviceAttachment::alloc(),
            &rootfs_url,
            false,
            VZDiskImageCachingMode::Automatic,
            VZDiskImageSynchronizationMode::Full,
        )
    }
    .map_err(|error| RunnerError::ConfigurationStep {
        step: "rootfs virtio block device",
        reason: ns_error_message(&error),
    })?;

    let disk_device = unsafe {
        VZVirtioBlockDeviceConfiguration::initWithAttachment(
            VZVirtioBlockDeviceConfiguration::alloc(),
            &disk_attachment,
        )
    };

    unsafe {
        disk_device.setBlockDeviceIdentifier(&NSString::from_str("firma-rootfs"));
    }

    let storage_devices: Retained<NSArray<VZStorageDeviceConfiguration>> =
        NSArray::from_retained_slice(&[Retained::into_super(disk_device)]);

    unsafe {
        config.setStorageDevices(&storage_devices);
    }

    Ok(())
}

/// Exposes the runtime directory and declared mounts through virtiofs.
fn configure_directory_shares(
    config: &VZVirtualMachineConfiguration,
    plan: &VmPlan,
) -> RunnerResult<()> {
    let mut names = Vec::with_capacity(plan.directory_shares.len());
    let mut directories = Vec::with_capacity(plan.directory_shares.len());

    for share in &plan.directory_shares {
        let name = NSString::from_str(&share.name);
        unsafe {
            VZMultipleDirectoryShare::validateName_error(&name).map_err(|error| {
                RunnerError::ConfigurationStep {
                    step: "virtiofs share name",
                    reason: ns_error_message(&error),
                }
            })?;
        }
        names.push(name);

        let url = nsurl_from_path(&share.source)?;
        directories.push(unsafe {
            VZSharedDirectory::initWithURL_readOnly(
                VZSharedDirectory::alloc(),
                &url,
                share.read_only,
            )
        });
    }

    let name_refs = names.iter().map(|name| &**name).collect::<Vec<_>>();
    let directory_refs = directories
        .iter()
        .map(|directory| &**directory)
        .collect::<Vec<_>>();
    let share_map: Retained<NSDictionary<NSString, VZSharedDirectory>> =
        NSDictionary::from_slices(&name_refs, &directory_refs);
    let multiple_share = unsafe {
        VZMultipleDirectoryShare::initWithDirectories(VZMultipleDirectoryShare::alloc(), &share_map)
    };

    let tag = NSString::from_str(FIRMA_VIRTIOFS_TAG);
    unsafe {
        VZVirtioFileSystemDeviceConfiguration::validateTag_error(&tag).map_err(|error| {
            RunnerError::ConfigurationStep {
                step: "virtiofs tag",
                reason: ns_error_message(&error),
            }
        })?;
    }

    let sharing_device = unsafe {
        VZVirtioFileSystemDeviceConfiguration::initWithTag(
            VZVirtioFileSystemDeviceConfiguration::alloc(),
            &tag,
        )
    };

    unsafe {
        sharing_device.setShare(Some(&multiple_share));
    }

    let sharing_devices = NSArray::from_retained_slice(&[Retained::into_super(sharing_device)]);

    unsafe {
        config.setDirectorySharingDevices(&sharing_devices);
    }

    Ok(())
}

/// Connects the VZ virtio console device to host-owned file descriptors.
fn configure_console_stdio(
    config: &VZVirtualMachineConfiguration,
    vm_reads_from: OwnedFd,
    vm_writes_to: OwnedFd,
) {
    let ns_read_handle = NSFileHandle::alloc();
    let ns_read_handle = NSFileHandle::initWithFileDescriptor_closeOnDealloc(
        ns_read_handle,
        vm_reads_from.into_raw_fd(),
        true,
    );

    let ns_write_handle = NSFileHandle::alloc();
    let ns_write_handle = NSFileHandle::initWithFileDescriptor_closeOnDealloc(
        ns_write_handle,
        vm_writes_to.into_raw_fd(),
        true,
    );

    let serial_attachment = unsafe {
        VZFileHandleSerialPortAttachment::initWithFileHandleForReading_fileHandleForWriting(
            VZFileHandleSerialPortAttachment::alloc(),
            Some(&ns_read_handle),
            Some(&ns_write_handle),
        )
    };

    let console_port = unsafe { VZVirtioConsolePortConfiguration::new() };
    unsafe {
        console_port.setAttachment(Some(&serial_attachment));
        console_port.setName(Some(&NSString::from_str("openfirma-console")));
        console_port.setIsConsole(true);
    }

    let console_device = unsafe { VZVirtioConsoleDeviceConfiguration::new() };

    unsafe {
        let ports = console_device.ports();
        ports.setMaximumPortCount(1);
        ports.setObject_atIndexedSubscript(Some(&console_port), 0);
    }

    let console_devices: Retained<NSArray<VZConsoleDeviceConfiguration>> =
        NSArray::from_retained_slice(&[Retained::into_super(console_device)]);

    unsafe {
        config.setConsoleDevices(&console_devices);
    }
}

/// Picks a CPU count inside the bounds accepted by Apple VZ.
fn clamped_cpu_count() -> NSUInteger {
    let min = unsafe { VZVirtualMachineConfiguration::minimumAllowedCPUCount() };
    let max = unsafe { VZVirtualMachineConfiguration::maximumAllowedCPUCount() };
    DEFAULT_CPU_COUNT.clamp(min, max)
}

/// Picks a memory size inside the bounds accepted by Apple VZ.
fn clamped_memory_size() -> u64 {
    let min = unsafe { VZVirtualMachineConfiguration::minimumAllowedMemorySize() };
    let max = unsafe { VZVirtualMachineConfiguration::maximumAllowedMemorySize() };
    DEFAULT_MEMORY_BYTES.clamp(min, max)
}

/// Converts a host filesystem path into an NSURL for VZ APIs.
fn nsurl_from_path(path: &Path) -> RunnerResult<Retained<NSURL>> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|source| RunnerError::HostOperation {
                action: "resolve current directory for VZ path",
                source,
            })?
            .join(path)
    };

    let string = absolute.to_str().ok_or_else(|| RunnerError::NonUtf8Path {
        path: absolute.clone(),
    })?;

    Ok(NSURL::fileURLWithPath(&NSString::from_str(string)))
}

/// Extracts a readable message from an Objective-C `NSError`.
pub fn ns_error_message(error: &NSError) -> String {
    error.localizedDescription().to_string()
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use super::*;
    use crate::runner::console::create_pipe;
    use crate::test_utils::{VZ_TEST_ROOTFS_SIZE_BYTES, vm_plan_fixture};

    #[test]
    fn vm_configuration_reaches_vz_validation_without_starting_vm() -> Result<()> {
        if unsafe { !VZVirtualMachine::isSupported() } {
            eprintln!("skipping VZ configuration test because Apple VZ is unsupported");
            return Ok(());
        }

        let (_temp, plan) = vm_plan_fixture(VZ_TEST_ROOTFS_SIZE_BYTES)?;

        let (vm_reads_from, _host_writes_to_vm) = create_pipe()?;
        let (_host_reads_from_vm, vm_writes_to) = create_pipe()?;
        let transport = VzTransportPlan::try_from(&plan)?;
        let vz = match Vz::from_plan(&plan, transport, vm_reads_from, vm_writes_to) {
            Ok(vz) => vz,
            Err(RunnerError::ConfigurationValidation { reason })
                if reason.contains("com.apple.security.virtualization") =>
            {
                eprintln!("skipping VZ configuration inspection because test binary is unsigned");
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };

        assert_eq!(unsafe { vz.config.storageDevices().count() }, 1);
        assert_eq!(unsafe { vz.config.directorySharingDevices().count() }, 1);
        assert_eq!(unsafe { vz.config.consoleDevices().count() }, 1);
        assert_eq!(unsafe { vz.config.socketDevices().count() }, 1);

        Ok(())
    }
}
