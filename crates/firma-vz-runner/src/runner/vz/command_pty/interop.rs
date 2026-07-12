use objc2::define_class;
use objc2_foundation::{NSObject, NSObjectProtocol};
use objc2_virtualization::{
    VZVirtioSocketConnection, VZVirtioSocketDevice, VZVirtioSocketListener,
    VZVirtioSocketListenerDelegate,
};

use super::data::{CommandPtyBridgeConfig, CommandPtyConnections};

/// Objective-C ivars retained by the command PTY data listener delegate.
#[derive(Debug)]
pub struct CommandPtyBridgeDelegateIvars {
    pub config: CommandPtyBridgeConfig,
    pub connections: CommandPtyConnections,
}

define_class!(
    #[unsafe(super(NSObject))]
    #[ivars = CommandPtyBridgeDelegateIvars]
    pub struct CommandPtyBridgeDelegate;

    unsafe impl NSObjectProtocol for CommandPtyBridgeDelegate {}

    unsafe impl VZVirtioSocketListenerDelegate for CommandPtyBridgeDelegate {
        #[unsafe(method(listener:shouldAcceptNewConnection:fromSocketDevice:))]
        #[allow(non_snake_case)]
        unsafe fn listener_shouldAcceptNewConnection_fromSocketDevice(
            &self,
            _listener: &VZVirtioSocketListener,
            connection: &VZVirtioSocketConnection,
            _socket_device: &VZVirtioSocketDevice,
        ) -> bool {
            self.accept_connection(connection)
        }
    }
);
