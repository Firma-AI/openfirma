//! Loopback egress guard: seccomp `user-notify` interceptor for `connect(2)`.
//!
//! A wrapped agent's direct connection to a loopback address bypasses
//! `HTTP_PROXY` and never reaches the Sidecar. To close that gap we trap every
//! `connect(2)` the agent makes and block the ones targeting a loopback address
//! that is not a sanctioned Firma endpoint (the proxy bridge or DNS stub).
//!
//! ## Two-process design
//!
//! seccomp's `user-notify` filter must be installed *inside* the sandbox, on
//! the agent's own process, but serviced by a supervisor that is **not** itself
//! subject to the filter. `bwrap` offers no way to hand the notification
//! listener fd back to the parent, so:
//!
//! 1. [`install_and_exec`] runs as a thin wrapper inside the sandbox (invoked by
//!    the entrypoint as `firma __egress-guard-install -- <agent> <args...>`). It
//!    installs a filter that returns `SECCOMP_RET_USER_NOTIF` for `connect`,
//!    sends the resulting listener fd to the host supervisor over a Unix socket
//!    (`SCM_RIGHTS`), then `execve`s the agent. The filter survives the exec.
//! 2. [`start`] runs the host-side supervisor (held in
//!    [`crate::routing::NetworkRuntime`]). It receives the listener fd and
//!    services notifications: it reads the target `sockaddr` from the agent via
//!    `/proc/<pid>/mem`, classifies it, and answers each `connect`.
//!
//! ## Allow vs deny, and the TOCTOU caveat
//!
//! The **deny** path is race-free: returning an errno does not re-execute the
//! syscall. The **allow** path answers with `SECCOMP_USER_NOTIF_FLAG_CONTINUE`,
//! which re-reads the agent-controlled `sockaddr` when the kernel re-runs the
//! syscall — the classic seccomp-notify TOCTOU window. We accept it because the
//! allow-list is just Firma's own loopback ports and, in structural mode, the
//! agent's network namespace is private, so even a won race reaches only the
//! agent's own loopback, never a host service. This is defense in depth layered
//! on the network-namespace boundary, not a standalone hard guarantee.
//!
//! Linux-only: seccomp and `/proc/<pid>/mem` are Linux primitives.

#![cfg(target_os = "linux")]
#![expect(
    unsafe_code,
    reason = "seccomp user-notify install and the NOTIF_RECV/SEND/ID_VALID ioctls have no safe wrapper in nix or libc; each unsafe call is a thin, checked FFI shim"
)]

use std::io::{self, IoSlice, IoSliceMut, Read, Seek, SeekFrom, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use firma_core::{RunAuditEvent, RunAuditMessage};
use nix::sys::socket::{ControlMessage, ControlMessageOwned, MsgFlags, recvmsg, sendmsg};

use crate::error::RunError;

// ── seccomp / BPF constants ─────────────────────────────────────────────────

const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x15;
const BPF_RET_K: u16 = 0x06;

const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;

const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

// AUDIT_ARCH_* and the `connect` syscall number for the targets OpenFirma
// supports. Other Linux arches fail naturally: the filter allows them through
// (it matches on the native arch only), so the guard simply does not engage.
#[cfg(target_arch = "x86_64")]
const NATIVE_AUDIT_ARCH: u32 = 0xC000_003E;
#[cfg(target_arch = "x86_64")]
const SYS_CONNECT_NR: u32 = 42;
#[cfg(target_arch = "aarch64")]
const NATIVE_AUDIT_ARCH: u32 = 0xC000_00B7;
#[cfg(target_arch = "aarch64")]
const SYS_CONNECT_NR: u32 = 203;

// AF_INET / AF_INET6 family discriminants as they appear in a `sockaddr`'s
// `sa_family`. Fixed on Linux (`<bits/socket.h>`): AF_INET = 2, AF_INET6 = 10.
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

/// Maximum `sockaddr` length we read from the agent. `sockaddr_in6` is 28
/// bytes; cap well above that but bounded so a bogus `addrlen` cannot make us
/// read megabytes from `/proc/<pid>/mem`.
const MAX_SOCKADDR_LEN: usize = 128;

// ── classification (pure, unit-tested) ──────────────────────────────────────

/// Outcome of classifying one `connect(2)` destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Let the syscall proceed (continue to the kernel).
    Allow,
    /// Block the syscall with `EACCES` and audit the attempt.
    Block,
}

/// Returns `true` when `ip` is a loopback destination, treating an
/// IPv4-mapped IPv6 address (`::ffff:127.0.0.1`) as loopback too.
fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|mapped| mapped.is_loopback())
        }
    }
}

/// Classifies a parsed destination against the sanctioned-port allow-list.
///
/// Non-loopback destinations always pass — the guard only governs loopback,
/// leaving external egress to the network-namespace / proxy boundary. Loopback
/// destinations pass only when the port is one of Firma's own endpoints.
pub(crate) fn classify(addr: SocketAddr, allow_ports: &[u16]) -> Verdict {
    if !is_loopback(addr.ip()) {
        return Verdict::Allow;
    }
    if allow_ports.contains(&addr.port()) {
        Verdict::Allow
    } else {
        Verdict::Block
    }
}

/// Parses a raw `sockaddr` blob into a [`SocketAddr`].
///
/// Returns `None` for address families we do not govern (e.g. `AF_UNIX`) or for
/// truncated buffers; the caller treats `None` as "allow" so non-IP connects
/// are never blocked.
pub(crate) fn parse_sockaddr(bytes: &[u8]) -> Option<SocketAddr> {
    if bytes.len() < 2 {
        return None;
    }
    // `sa_family` is host-endian (a C `unsigned short`).
    let family = u16::from_ne_bytes([bytes[0], bytes[1]]);
    match family {
        AF_INET => {
            if bytes.len() < 8 {
                return None;
            }
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let octets: [u8; 4] = bytes[4..8].try_into().ok()?;
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
        }
        AF_INET6 => {
            if bytes.len() < 24 {
                return None;
            }
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            // sockaddr_in6: family(2) port(2) flowinfo(4) addr(16) ...
            let octets: [u8; 16] = bytes[8..24].try_into().ok()?;
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        _ => None,
    }
}

// ── /proc/<pid>/mem reader (safe std I/O) ───────────────────────────────────

/// Reads `len` bytes at virtual address `addr` from process `pid` via
/// `/proc/<pid>/mem`. Used to recover the `sockaddr` a `connect(2)` points at.
///
/// This is plain file I/O — no `process_vm_readv` FFI required. It can fail
/// (process gone, permission denied under an aggressive ptrace scope); callers
/// treat a read failure as "allow" so the guard never wedges the agent on an
/// unreadable address.
fn read_proc_mem(pid: u32, addr: u64, len: usize) -> io::Result<Vec<u8>> {
    let len = len.min(MAX_SOCKADDR_LEN);
    let mut file = std::fs::File::open(format!("/proc/{pid}/mem"))?;
    file.seek(SeekFrom::Start(addr))?;
    let mut buf = vec![0_u8; len];
    file.read_exact(&mut buf)?;
    Ok(buf)
}

// ── BPF program (safe builder) ──────────────────────────────────────────────

fn sf(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// Builds the cBPF program: notify on `connect` for the native arch, allow
/// everything else (including foreign-arch syscalls).
fn build_connect_notify_program() -> [libc::sock_filter; 6] {
    [
        // 0: load arch
        sf(BPF_LD_W_ABS, 0, 0, SECCOMP_DATA_ARCH_OFFSET),
        // 1: if arch != native -> allow (skip 3 to idx5)
        sf(BPF_JMP_JEQ_K, 0, 3, NATIVE_AUDIT_ARCH),
        // 2: load syscall nr
        sf(BPF_LD_W_ABS, 0, 0, SECCOMP_DATA_NR_OFFSET),
        // 3: if nr != connect -> allow (skip 1 to idx5)
        sf(BPF_JMP_JEQ_K, 0, 1, SYS_CONNECT_NR),
        // 4: connect -> notify the supervisor
        sf(BPF_RET_K, 0, 0, libc::SECCOMP_RET_USER_NOTIF),
        // 5: allow
        sf(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW),
    ]
}

// ── seccomp install (FFI) ───────────────────────────────────────────────────

/// Installs the connect-notify filter on the current process and returns the
/// notification listener fd.
fn install_connect_notifier() -> io::Result<OwnedFd> {
    // Unprivileged seccomp requires no-new-privs.
    // SAFETY: prctl with PR_SET_NO_NEW_PRIVS takes scalar args and has no
    // memory effects; a non-zero return is surfaced as an io error.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }

    let mut program = build_connect_notify_program();
    let prog = libc::sock_fprog {
        len: u16::try_from(program.len()).unwrap_or(u16::MAX),
        filter: program.as_mut_ptr(),
    };

    // SAFETY: SYS_seccomp with SET_MODE_FILTER reads `prog` (a valid
    // sock_fprog pointing at `program`, which outlives the call) and returns a
    // new listener fd on success or -1 with errno set.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_NEW_LISTENER,
            std::ptr::from_ref(&prog).cast::<libc::c_void>(),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = RawFd::try_from(fd).map_err(|_| io::Error::other("seccomp returned an invalid fd"))?;
    // SAFETY: `fd` is a fresh, owned fd returned by the kernel; we take sole
    // ownership so it is closed exactly once on drop.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

// ── notify ioctls (FFI) ─────────────────────────────────────────────────────

const IOC_WRITE: u64 = 1;
const IOC_READ: u64 = 2;
const SECCOMP_IOC_MAGIC: u64 = b'!' as u64;

const fn ioc(dir: u64, nr: u64, size: usize) -> libc::c_ulong {
    ((dir << 30) | (SECCOMP_IOC_MAGIC << 8) | nr | ((size as u64) << 16)) as libc::c_ulong
}

fn notif_recv_req() -> libc::c_ulong {
    ioc(
        IOC_READ | IOC_WRITE,
        0,
        std::mem::size_of::<libc::seccomp_notif>(),
    )
}
fn notif_send_req() -> libc::c_ulong {
    ioc(
        IOC_READ | IOC_WRITE,
        1,
        std::mem::size_of::<libc::seccomp_notif_resp>(),
    )
}
fn notif_id_valid_req() -> libc::c_ulong {
    ioc(IOC_WRITE, 2, std::mem::size_of::<u64>())
}

/// Blocks until a `connect` notification arrives, filling `req`.
fn notif_recv(fd: RawFd, req: &mut libc::seccomp_notif) -> io::Result<()> {
    *req = unsafe { std::mem::zeroed() };
    // SAFETY: ioctl writes one `seccomp_notif` into `req` (valid, sized to the
    // kernel's struct). Return < 0 means errno is set.
    let rc = unsafe { libc::ioctl(fd, notif_recv_req(), std::ptr::from_mut(req)) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Answers a notification.
fn notif_send(fd: RawFd, resp: &libc::seccomp_notif_resp) -> io::Result<()> {
    // SAFETY: ioctl reads one `seccomp_notif_resp` from `resp`. A < 0 return
    // sets errno; ENOENT (target gone) is mapped by the caller.
    let rc = unsafe { libc::ioctl(fd, notif_send_req(), std::ptr::from_ref(resp)) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Confirms the notification `id` still refers to a live, un-answered request.
/// Guards against pid reuse between reading `/proc/<pid>/mem` and answering.
fn notif_id_is_valid(fd: RawFd, id: u64) -> bool {
    // SAFETY: ioctl reads one u64 (`id`); returns 0 when still valid.
    let rc = unsafe { libc::ioctl(fd, notif_id_valid_req(), std::ptr::from_ref(&id)) };
    rc == 0
}

// ── installer side (runs inside the sandbox) ────────────────────────────────

/// Installs the guard filter, hands the listener fd to the host supervisor over
/// `socket_path`, then `execve`s the agent. Never returns on success.
///
/// # Errors
///
/// Returns a [`RunError`] when the supervisor socket cannot be reached, the
/// filter cannot be installed, the fd cannot be sent, or `exec` fails. The
/// caller (the `__egress-guard-install` subcommand) maps the error to a
/// fail-closed non-zero exit.
pub fn install_and_exec(
    socket_path: &Path,
    argv: &[String],
) -> Result<std::convert::Infallible, RunError> {
    let (executable, agent_args) = argv
        .split_first()
        .ok_or_else(|| RunError::Internal("egress guard: empty agent argv".to_string()))?;

    // Connect BEFORE installing the filter: the AF_UNIX connect must not be
    // trapped by our own connect filter (the supervisor is not servicing yet).
    let stream = UnixStream::connect(socket_path).map_err(|error| {
        RunError::Internal(format!(
            "egress guard: connect supervisor socket {}: {error}",
            socket_path.display()
        ))
    })?;

    let listener_fd = install_connect_notifier()
        .map_err(|error| RunError::Internal(format!("egress guard: install filter: {error}")))?;

    send_listener_fd(&stream, listener_fd.as_raw_fd())
        .map_err(|error| RunError::Internal(format!("egress guard: send listener fd: {error}")))?;
    drop(listener_fd); // supervisor holds its own copy now
    drop(stream);

    // `exec` keeps the installed seccomp filter; the agent inherits it.
    let error = std::process::Command::new(executable)
        .args(agent_args)
        .exec();
    Err(RunError::Spawn(format!(
        "egress guard: exec {executable}: {error}"
    )))
}

/// Sends a single fd plus a one-byte payload over a connected Unix stream using
/// `SCM_RIGHTS`.
fn send_listener_fd(stream: &UnixStream, fd: RawFd) -> io::Result<()> {
    let payload = [0_u8; 1];
    let iov = [IoSlice::new(&payload)];
    let fds = [fd];
    let cmsg = [ControlMessage::ScmRights(&fds)];
    sendmsg::<()>(stream.as_raw_fd(), &iov, &cmsg, MsgFlags::empty(), None)
        .map_err(|errno| io::Error::from_raw_os_error(errno as i32))?;
    Ok(())
}

/// Receives a single fd sent with [`send_listener_fd`].
fn recv_listener_fd(stream: &UnixStream) -> io::Result<OwnedFd> {
    let mut payload = [0_u8; 1];
    let mut iov = [IoSliceMut::new(&mut payload)];
    let mut cmsg_space = nix::cmsg_space!([RawFd; 1]);
    let msg = recvmsg::<()>(
        stream.as_raw_fd(),
        &mut iov,
        Some(&mut cmsg_space),
        MsgFlags::empty(),
    )
    .map_err(|errno| io::Error::from_raw_os_error(errno as i32))?;

    for cmsg in msg
        .cmsgs()
        .map_err(|errno| io::Error::from_raw_os_error(errno as i32))?
    {
        if let ControlMessageOwned::ScmRights(fds) = cmsg
            && let Some(&fd) = fds.first()
        {
            // SAFETY: `fd` was just transferred to us by the kernel via
            // SCM_RIGHTS; we take sole ownership.
            return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
        }
    }
    Err(io::Error::other(
        "no fd received from egress guard installer",
    ))
}

// ── supervisor side (runs on the host) ──────────────────────────────────────

/// Where and how blocked attempts are reported for signed auditing — the
/// `firma run` audit channel to the Sidecar.
#[derive(Debug, Clone)]
pub struct AuditChannel {
    /// Sidecar run-audit control socket (`FIRMA_RUN_AUDIT_SOCK`).
    pub socket_path: PathBuf,
    /// Session and agent identity stamped onto each message.
    pub session_id: String,
    pub agent_id: String,
}

/// Inputs to [`start`].
#[derive(Debug, Clone)]
pub struct SupervisorConfig {
    /// Unix socket the in-sandbox installer connects to, to hand over the
    /// listener fd. Must be reachable from inside the sandbox (bind-mounted).
    pub socket_path: PathBuf,
    /// Loopback ports the agent may still reach (proxy bridge, DNS stub).
    pub allow_ports: Vec<u16>,
    /// Optional sink for signed audit reports. When `None` (e.g. an external
    /// Sidecar whose env we do not control), blocks are still enforced but only
    /// logged locally.
    pub report: Option<AuditChannel>,
}

/// Live handle to a running guard supervisor. Dropping it stops the supervisor
/// thread and removes the control socket.
pub struct EgressGuardHandle {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    socket_path: PathBuf,
}

impl Drop for EgressGuardHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

/// Binds the control socket and spawns the supervisor thread.
///
/// The thread waits for the in-sandbox installer to connect and pass the
/// notification listener fd, then services `connect` notifications until the
/// returned handle is dropped.
///
/// # Errors
///
/// Returns a [`RunError`] when the control socket directory cannot be created
/// or the socket cannot be bound.
pub fn start(config: SupervisorConfig) -> Result<EgressGuardHandle, RunError> {
    if let Some(parent) = config.socket_path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| RunError::Backend {
            backend: "egress_guard".to_string(),
            reason: format!("create guard socket dir {}: {error}", parent.display()),
        })?;
    }
    let _ = std::fs::remove_file(&config.socket_path);
    let listener = UnixListener::bind(&config.socket_path).map_err(|error| RunError::Backend {
        backend: "egress_guard".to_string(),
        reason: format!(
            "bind guard socket {}: {error}",
            config.socket_path.display()
        ),
    })?;
    listener
        .set_nonblocking(true)
        .map_err(|error| RunError::Backend {
            backend: "egress_guard".to_string(),
            reason: format!("set guard socket non-blocking: {error}"),
        })?;

    let stop = Arc::new(AtomicBool::new(false));
    let socket_path = config.socket_path.clone();
    tracing::info!(
        socket = %socket_path.display(),
        allow_ports = ?config.allow_ports,
        reporting = config.report.is_some(),
        "loopback egress guard started"
    );

    let thread_stop = Arc::clone(&stop);
    let thread = std::thread::Builder::new()
        .name("firma-egress-guard".to_string())
        .spawn(move || supervise(&listener, &config, &thread_stop))
        .map_err(|error| RunError::Backend {
            backend: "egress_guard".to_string(),
            reason: format!("spawn guard thread: {error}"),
        })?;

    Ok(EgressGuardHandle {
        stop,
        thread: Some(thread),
        socket_path,
    })
}

/// Supervisor body: wait for the installer's fd, then run the notify loop.
fn supervise(listener: &UnixListener, config: &SupervisorConfig, stop: &AtomicBool) {
    let Some(stream) = accept_installer(listener, stop) else {
        return;
    };
    let listener_fd = match recv_listener_fd(&stream) {
        Ok(fd) => fd,
        Err(error) => {
            tracing::warn!(%error, "egress guard: failed to receive listener fd; guard inactive");
            return;
        }
    };
    drop(stream);
    notify_loop(listener_fd.as_raw_fd(), config, stop);
}

/// Polls the (non-blocking) control listener for the single installer
/// connection, honoring the stop flag.
fn accept_installer(listener: &UnixListener, stop: &AtomicBool) -> Option<UnixStream> {
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _addr)) => return Some(stream),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(error) => {
                tracing::warn!(%error, "egress guard: accept failed");
                return None;
            }
        }
    }
    None
}

/// Services `connect` notifications until `stop` is set or the listener fd
/// closes (agent exited).
fn notify_loop(notify_fd: RawFd, config: &SupervisorConfig, stop: &AtomicBool) {
    while !stop.load(Ordering::SeqCst) {
        if !wait_readable(notify_fd, Duration::from_millis(200)) {
            continue;
        }
        let mut req: libc::seccomp_notif = unsafe { std::mem::zeroed() };
        match notif_recv(notify_fd, &mut req) {
            Ok(()) => handle_notification(notify_fd, &req, config),
            Err(error) => {
                // ENOENT: target died before we read it — just continue.
                // EINTR: retry. Anything else: the listener is likely gone.
                if !matches!(error.raw_os_error(), Some(libc::ENOENT | libc::EINTR)) {
                    tracing::debug!(%error, "egress guard: notify recv ended");
                    return;
                }
            }
        }
    }
}

/// Classifies one notification and answers it (allow-continue or block-EACCES).
fn handle_notification(notify_fd: RawFd, req: &libc::seccomp_notif, config: &SupervisorConfig) {
    let verdict = classify_notification(req, &config.allow_ports);
    match verdict {
        NotifOutcome::Allow => {
            let resp = libc::seccomp_notif_resp {
                id: req.id,
                val: 0,
                error: 0,
                flags: u32::try_from(libc::SECCOMP_USER_NOTIF_FLAG_CONTINUE).unwrap_or(0),
            };
            let _ = notif_send(notify_fd, &resp);
        }
        NotifOutcome::Block(addr) => {
            // Re-validate the request id right before answering, in case the
            // target died and its pid was recycled while we read its memory.
            if !notif_id_is_valid(notify_fd, req.id) {
                return;
            }
            let resp = libc::seccomp_notif_resp {
                id: req.id,
                val: 0,
                error: -libc::EACCES,
                flags: 0,
            };
            let _ = notif_send(notify_fd, &resp);
            tracing::warn!(dst = %addr, "blocked agent connection to loopback");
            if let Some(channel) = &config.report {
                report_event(channel, addr);
            }
        }
    }
}

enum NotifOutcome {
    Allow,
    Block(SocketAddr),
}

/// Reads and classifies the destination of a `connect` notification.
///
/// Any failure to read or parse the address resolves to `Allow`: the guard
/// only ever blocks a destination it positively identifies as non-sanctioned
/// loopback, so an unreadable address never wedges the agent.
fn classify_notification(req: &libc::seccomp_notif, allow_ports: &[u16]) -> NotifOutcome {
    // connect(fd, sockaddr_ptr, addrlen): args[1] = pointer, args[2] = len.
    let addr_ptr = req.data.args[1];
    let addr_len = usize::try_from(req.data.args[2]).unwrap_or(0);
    if addr_ptr == 0 || addr_len < 2 {
        return NotifOutcome::Allow;
    }
    let Ok(bytes) = read_proc_mem(req.pid, addr_ptr, addr_len) else {
        return NotifOutcome::Allow;
    };
    let Some(addr) = parse_sockaddr(&bytes) else {
        return NotifOutcome::Allow;
    };
    match classify(addr, allow_ports) {
        Verdict::Allow => NotifOutcome::Allow,
        Verdict::Block => NotifOutcome::Block(addr),
    }
}

/// `poll(2)` for readability with a timeout so the loop can observe the stop
/// flag.
fn wait_readable(fd: RawFd, timeout: Duration) -> bool {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let millis = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
    // SAFETY: poll reads/writes the single pollfd we own for the call.
    let rc = unsafe { libc::poll(std::ptr::from_mut(&mut pfd), 1, millis) };
    rc > 0 && (pfd.revents & libc::POLLIN) != 0
}

/// Best-effort: forward a blocked attempt to the Sidecar over the `firma run`
/// audit channel as a newline-delimited JSON [`RunAuditMessage`].
fn report_event(channel: &AuditChannel, addr: SocketAddr) {
    let message = RunAuditMessage {
        session_id: channel.session_id.clone(),
        agent_id: channel.agent_id.clone(),
        event: RunAuditEvent::LoopbackBlocked {
            dst_ip: addr.ip().to_string(),
            dst_port: addr.port(),
        },
    };
    let Ok(mut line) = serde_json::to_string(&message) else {
        return;
    };
    line.push('\n');

    match UnixStream::connect(&channel.socket_path) {
        Ok(mut stream) => {
            if let Err(error) = stream.write_all(line.as_bytes()) {
                tracing::debug!(%error, "egress guard: failed to write audit message");
            }
        }
        Err(error) => {
            tracing::debug!(%error, "egress guard: run-audit socket unreachable");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROXY: u16 = 18080;
    const DNS: u16 = 53;

    fn allow() -> Vec<u16> {
        vec![PROXY, DNS]
    }

    #[test]
    fn loopback_to_unsanctioned_port_blocks() {
        let addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        assert_eq!(classify(addr, &allow()), Verdict::Block);
    }

    #[test]
    fn loopback_to_allowed_port_passes() {
        let addr: SocketAddr = "127.0.0.1:18080".parse().unwrap();
        assert_eq!(classify(addr, &allow()), Verdict::Allow);
    }

    #[test]
    fn non_dot_one_loopback_still_blocks() {
        // 127.0.0.0/8 is all loopback, not just 127.0.0.1.
        let addr: SocketAddr = "127.9.9.9:6379".parse().unwrap();
        assert_eq!(classify(addr, &allow()), Verdict::Block);
    }

    #[test]
    fn ipv6_loopback_blocks() {
        let addr: SocketAddr = "[::1]:6379".parse().unwrap();
        assert_eq!(classify(addr, &allow()), Verdict::Block);
    }

    #[test]
    fn ipv4_mapped_loopback_blocks() {
        let addr: SocketAddr = "[::ffff:127.0.0.1]:6379".parse().unwrap();
        assert_eq!(classify(addr, &allow()), Verdict::Block);
    }

    #[test]
    fn external_destination_always_allowed() {
        let v4: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let v6: SocketAddr = "[2606:2800:220:1:248:1893:25c8:1946]:443".parse().unwrap();
        assert_eq!(classify(v4, &allow()), Verdict::Allow);
        assert_eq!(classify(v6, &allow()), Verdict::Allow);
    }

    #[test]
    fn parse_ipv4_sockaddr() {
        // family=AF_INET(2) LE, port=18080 BE, addr=127.0.0.1
        let mut bytes = vec![0_u8; 16];
        bytes[0..2].copy_from_slice(&AF_INET.to_ne_bytes());
        bytes[2..4].copy_from_slice(&18080_u16.to_be_bytes());
        bytes[4..8].copy_from_slice(&[127, 0, 0, 1]);
        let addr = parse_sockaddr(&bytes).expect("parse");
        assert_eq!(addr, "127.0.0.1:18080".parse().unwrap());
    }

    #[test]
    fn parse_ipv6_sockaddr() {
        let mut bytes = vec![0_u8; 28];
        bytes[0..2].copy_from_slice(&AF_INET6.to_ne_bytes());
        bytes[2..4].copy_from_slice(&53_u16.to_be_bytes());
        bytes[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        let addr = parse_sockaddr(&bytes).expect("parse");
        assert_eq!(addr, "[::1]:53".parse().unwrap());
    }

    #[test]
    fn parse_non_ip_family_is_none() {
        // AF_UNIX = 1
        let bytes = vec![1_u8, 0, 0, 0, 0, 0, 0, 0];
        assert!(parse_sockaddr(&bytes).is_none());
    }

    #[test]
    fn parse_truncated_is_none() {
        assert!(parse_sockaddr(&[2]).is_none());
    }

    #[test]
    fn bpf_program_has_expected_shape() {
        let prog = build_connect_notify_program();
        assert_eq!(prog.len(), 6);
        assert_eq!(prog[4].k, libc::SECCOMP_RET_USER_NOTIF);
        assert_eq!(prog[5].k, SECCOMP_RET_ALLOW);
        assert_eq!(prog[3].k, SYS_CONNECT_NR);
    }
}
