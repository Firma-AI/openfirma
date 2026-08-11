use std::path::Path;
use std::time::Duration;

use socket2::{Domain, SockAddr, Socket, Type};

/// Attempt one nonblocking Unix-domain connection within `timeout`.
pub fn connect_with_timeout(path: &Path, timeout: Duration) -> bool {
    if timeout.is_zero() {
        return false;
    }
    let Ok(address) = SockAddr::unix(path) else {
        return false;
    };
    let Ok(socket) = Socket::new(Domain::UNIX, Type::STREAM, None) else {
        return false;
    };
    socket.connect_timeout(&address, timeout).is_ok()
}
