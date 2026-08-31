use std::io;

use tokio::net::UnixStream;

/// The effective uid of the process on the other side of `stream`.
///
/// Tokio selects the platform credential API: `SO_PEERCRED`, `getpeereid`, or
/// `getpeerucred`, depending on the Unix target.
#[cfg(unix)]
pub fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    stream.peer_cred().map(|credentials| credentials.uid())
}

/// The uid of the current process.
#[cfg(unix)]
pub fn current_uid() -> u32 {
    nix::unistd::Uid::current().as_raw()
}

/// Make a freshly-bound Unix socket owner-only.
pub async fn set_socket_permissions(path: &std::path::Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await
}
