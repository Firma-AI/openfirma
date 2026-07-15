//! Out-of-sandbox broker transport for the secret shim.
//!
//! A sandbox shim connects to this broker over a Unix domain socket and hands
//! over the file descriptors of the wrapped tool using `SCM_RIGHTS`, together
//! with a small JSON handshake describing the launch.
//!
//! See `docs/architecture/secrets-interception.md`.

#![expect(
    unsafe_code,
    reason = "descriptors received via SCM_RIGHTS have no safe nix wrapper into OwnedFd; each unsafe is a thin, checked shim taking sole ownership of a just-transferred fd"
)]

use std::io::{self, IoSlice, IoSliceMut};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use nix::sys::socket::{ControlMessage, ControlMessageOwned, MsgFlags, recvmsg, sendmsg};
use serde::{Deserialize, Serialize};

/// Maximum number of descriptors accepted in a single handshake.
const MAX_FDS: usize = 8;

/// Maximum handshake payload size (length-prefixed JSON), in bytes.
const MAX_HANDSHAKE_LEN: usize = 64 * 1024;

/// Role of a descriptor handed to the broker.
///
/// Roles are listed in the handshake in the same order the descriptors are
/// passed via `SCM_RIGHTS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FdRole {
    /// Stream carrying bytes from the agent toward the wrapped tool — the
    /// rehydration target (placeholder → secret).
    AgentToTool,
    /// Stream carrying bytes from the wrapped tool toward the agent — the
    /// masking target (secret → placeholder).
    ToolToAgent,
}

/// Shim → broker handshake, sent once per wrapped-tool launch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Handshake {
    /// Full launch argv of the wrapped tool; becomes the Cedar `resource.id`.
    pub argv: Vec<String>,
    /// Roles of the passed descriptors, aligned with the `SCM_RIGHTS` fd order.
    pub fds: Vec<FdRole>,
}

/// A decoded handshake together with the descriptors that accompanied it.
#[derive(Debug)]
pub struct AcceptedHandshake {
    /// The decoded handshake.
    pub handshake: Handshake,
    /// Descriptors received via `SCM_RIGHTS`, in the order declared by
    /// [`Handshake::fds`].
    pub fds: Vec<OwnedFd>,
}

/// Broker-side listener for shim handshakes on a Unix domain socket.
#[derive(Debug)]
pub struct BrokerListener {
    listener: UnixListener,
    path: PathBuf,
}

impl BrokerListener {
    /// Bind a listener at `path`, removing any stale socket file first.
    ///
    /// # Errors
    ///
    /// Returns the underlying I/O error if removing a stale socket (other than
    /// a missing one) or binding fails.
    pub fn bind(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        // A leftover socket file from a previous run makes `bind` fail with
        // EADDRINUSE; remove it best-effort, tolerating "not found".
        if let Err(error) = std::fs::remove_file(&path)
            && error.kind() != io::ErrorKind::NotFound
        {
            return Err(error);
        }
        let listener = UnixListener::bind(&path)?;
        Ok(Self { listener, path })
    }

    /// Accept one shim connection and read its handshake and descriptors.
    ///
    /// # Errors
    ///
    /// Returns an error if accepting, receiving, or decoding fails, including
    /// when the received descriptor count does not match the declared roles
    /// (fail closed).
    pub fn accept(&self) -> io::Result<AcceptedHandshake> {
        let (stream, _addr) = self.listener.accept()?;
        recv_handshake(&stream)
    }

    /// The bound socket path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for BrokerListener {
    fn drop(&mut self) {
        // Best-effort removal of the socket file on shutdown.
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Send a handshake and its descriptors over a connected stream.
///
/// The payload is a little-endian `u32` length prefix followed by the JSON
/// handshake; the descriptors ride along as `SCM_RIGHTS` ancillary data.
///
/// # Errors
///
/// Returns an error if the descriptor count disagrees with the declared roles,
/// too many descriptors are passed, serialization fails, or the socket send
/// fails.
pub fn send_handshake(
    stream: &UnixStream,
    handshake: &Handshake,
    fds: &[BorrowedFd<'_>],
) -> io::Result<()> {
    if fds.len() != handshake.fds.len() {
        return Err(io::Error::other(
            "descriptor count does not match declared roles",
        ));
    }
    if fds.len() > MAX_FDS {
        return Err(io::Error::other("too many descriptors in handshake"));
    }

    let json = serde_json::to_vec(handshake).map_err(io::Error::other)?;
    let len =
        u32::try_from(json.len()).map_err(|_| io::Error::other("handshake payload too large"))?;
    let len_bytes = len.to_le_bytes();
    let iov = [IoSlice::new(&len_bytes), IoSlice::new(&json)];

    let raw_fds: Vec<RawFd> = fds.iter().map(AsRawFd::as_raw_fd).collect();
    if raw_fds.is_empty() {
        sendmsg::<()>(stream.as_raw_fd(), &iov, &[], MsgFlags::empty(), None)
    } else {
        let cmsg = [ControlMessage::ScmRights(raw_fds.as_slice())];
        sendmsg::<()>(stream.as_raw_fd(), &iov, &cmsg, MsgFlags::empty(), None)
    }
    .map_err(|errno| io::Error::from_raw_os_error(errno as i32))?;
    Ok(())
}

/// Receive a handshake and its descriptors from a connected stream.
///
/// # Errors
///
/// Returns an error if the socket receive fails, the payload is truncated or
/// oversized, JSON decoding fails, or the received descriptor count does not
/// match the declared roles (fail closed).
pub fn recv_handshake(stream: &UnixStream) -> io::Result<AcceptedHandshake> {
    let mut buf = vec![0_u8; MAX_HANDSHAKE_LEN];

    let received;
    let mut fds: Vec<OwnedFd> = Vec::new();
    {
        let mut iov = [IoSliceMut::new(&mut buf)];
        let mut cmsg_space = nix::cmsg_space!([RawFd; MAX_FDS]);
        let msg = recvmsg::<()>(
            stream.as_raw_fd(),
            &mut iov,
            Some(&mut cmsg_space),
            MsgFlags::empty(),
        )
        .map_err(|errno| io::Error::from_raw_os_error(errno as i32))?;

        received = msg.bytes;
        for cmsg in msg
            .cmsgs()
            .map_err(|errno| io::Error::from_raw_os_error(errno as i32))?
        {
            if let ControlMessageOwned::ScmRights(raw) = cmsg {
                for fd in raw {
                    // SAFETY: each fd was just transferred to us by the kernel
                    // via SCM_RIGHTS; we take sole ownership of it here.
                    fds.push(unsafe { OwnedFd::from_raw_fd(fd) });
                }
            }
        }
    }

    let len_bytes: [u8; 4] = buf
        .get(0..4)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| io::Error::other("handshake shorter than length prefix"))?;
    let len = usize::try_from(u32::from_le_bytes(len_bytes))
        .map_err(|_| io::Error::other("invalid handshake length"))?;
    let end = 4usize
        .checked_add(len)
        .ok_or_else(|| io::Error::other("handshake length overflow"))?;
    if received != end {
        return Err(io::Error::other("truncated or oversized handshake payload"));
    }

    let json = buf
        .get(4..end)
        .ok_or_else(|| io::Error::other("handshake payload out of range"))?;
    let handshake: Handshake = serde_json::from_slice(json).map_err(io::Error::other)?;
    if handshake.fds.len() != fds.len() {
        return Err(io::Error::other(
            "received descriptor count does not match handshake roles",
        ));
    }

    Ok(AcceptedHandshake { handshake, fds })
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::os::fd::AsFd;

    use super::*;

    fn sample_handshake(fds: Vec<FdRole>) -> Handshake {
        Handshake {
            argv: vec!["bws".to_string(), "secret".to_string(), "get".to_string()],
            fds,
        }
    }

    #[test]
    fn handshake_and_descriptor_roundtrip() {
        let (client, server) = UnixStream::pair().expect("socketpair");
        let (mut reader, writer) = std::io::pipe().expect("pipe");
        let handshake = sample_handshake(vec![FdRole::ToolToAgent]);

        send_handshake(&client, &handshake, &[writer.as_fd()]).expect("send handshake");
        let accepted = recv_handshake(&server).expect("recv handshake");

        assert_eq!(accepted.handshake, handshake);
        assert_eq!(accepted.fds.len(), 1);

        // The received descriptor must be a working duplicate of our pipe write
        // end: writing through it is readable from the retained read end.
        drop(writer);
        let received = accepted.fds.into_iter().next().expect("one descriptor");
        let mut received_writer = std::fs::File::from(received);
        received_writer
            .write_all(b"ping")
            .expect("write via received fd");
        drop(received_writer);

        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).expect("read pipe");
        assert_eq!(buf, b"ping");
    }

    #[test]
    fn listener_binds_accepts_and_cleans_up() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket_path = dir.path().join("broker.sock");

        let accepted = {
            let listener = BrokerListener::bind(&socket_path).expect("bind");
            assert_eq!(listener.path(), socket_path);
            assert!(socket_path.exists());

            let client = UnixStream::connect(&socket_path).expect("connect");
            let handshake = Handshake {
                argv: vec!["npx".to_string(), "@playwright/mcp".to_string()],
                fds: Vec::new(),
            };
            send_handshake(&client, &handshake, &[]).expect("send handshake");
            listener.accept().expect("accept handshake")
        };

        assert_eq!(accepted.handshake.argv, ["npx", "@playwright/mcp"]);
        assert!(accepted.fds.is_empty());
        // The listener was dropped at the end of the block; the socket file is
        // removed.
        assert!(!socket_path.exists());
    }

    #[test]
    fn send_rejects_declared_role_and_fd_count_mismatch() {
        let (client, _server) = UnixStream::pair().expect("socketpair");
        // Declares one role but passes zero descriptors.
        let handshake = sample_handshake(vec![FdRole::ToolToAgent]);
        let error = send_handshake(&client, &handshake, &[]).expect_err("count mismatch");
        assert_eq!(error.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn recv_rejects_payload_without_valid_length_prefix() {
        let (client, server) = UnixStream::pair().expect("socketpair");
        // Two raw bytes: fewer than the four-byte length prefix declares.
        (&client).write_all(b"xx").expect("write raw bytes");
        drop(client);

        let error = recv_handshake(&server).expect_err("truncated payload");
        assert_eq!(error.kind(), io::ErrorKind::Other);
    }
}
