//! Loopback egress guard: seccomp `user-notify` interceptor for `connect(2)`.
//!
//! A wrapped agent's direct connection to a loopback address bypasses
//! `HTTP_PROXY` and never reaches the Sidecar. To close that gap we trap every
//! `connect(2)` the agent makes and block the ones targeting a loopback address
//! that is not a sanctioned Firma endpoint (the proxy bridge or DNS stub).
//!
//! A loopback destination is also allowed when the agent's own network namespace
//! has a listener on that port — a service the agent started inside its jail
//! (e.g. a test server binding `127.0.0.1:0`). Because the guard runs only in
//! structural mode, that namespace is private, so such a listener is by
//! construction in-jail and reachable only from the agent itself; the
//! `netns_local_ports` probe reads `/proc/<pid>/net/*` to recognize it.
//!
//! ## Two-process design
//!
//! seccomp's `user-notify` filter must be installed *inside* the sandbox, on
//! the agent's own process, but serviced by a supervisor that is **not** itself
//! subject to the filter. `bwrap` offers no way to hand the notification
//! listener fd back to the parent, so:
//!
//! 1. [`install_and_exec`] runs as a thin wrapper inside the sandbox (invoked by
//!    the entrypoint as `firma __egress-guarded-run -- <agent> <args...>`). It
//!    installs a filter that returns `SECCOMP_RET_USER_NOTIF` for `connect`,
//!    sends the resulting listener fd to the host supervisor over a Unix socket
//!    (`SCM_RIGHTS`), then `execve`s the agent. The filter survives the exec.
//! 2. [`start`] runs the host-side supervisor (held in
//!    [`crate::routing::NetworkRuntime`]). It receives the listener fd and
//!    services notifications: it reads the target `sockaddr` from the agent via
//!    `process_vm_readv(2)`, classifies it, and answers each `connect`.
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
//! A related short-read hazard on the read path is also handled fail-closed:
//! `process_vm_readv(2)` can return fewer bytes than requested (e.g. a sockaddr
//! straddling a page boundary with the second page unmapped), which would leave
//! the buffer tail zero-filled and misclassify a loopback destination as
//! `0.0.0.0`. `read_remote_mem` rejects any short read, so the caller blocks
//! rather than allowing on a partial read.
//!
//! Linux-only: seccomp and `process_vm_readv(2)` are Linux primitives.

#![cfg(target_os = "linux")]
#![expect(
    unsafe_code,
    reason = "seccomp user-notify install and the NOTIF_RECV/SEND/ID_VALID ioctls have no safe wrapper in nix or libc; each unsafe call is a thin, checked FFI shim"
)]

use std::collections::BTreeSet;
use std::io::{self, IoSlice, IoSliceMut, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, sync_channel};
use std::thread::JoinHandle;
use std::time::Duration;

use firma_core::{RunAuditEvent, RunAuditMessage};
use firma_identifiers::AgentId;
use nix::sys::socket::{ControlMessage, ControlMessageOwned, MsgFlags, recvmsg, sendmsg};
use nix::unistd::Pid;

use crate::error::RunError;

// ── seccomp / BPF constants ─────────────────────────────────────────────────

const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x15;
const BPF_RET_K: u16 = 0x06;

const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;

const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

/// `SECCOMP_USER_NOTIF_FLAG_CONTINUE` narrowed to the `seccomp_notif_resp.flags`
/// field width. Statically checked against libc so the cast can never silently
/// truncate into a wrong (fake-success) response.
const USER_NOTIF_FLAG_CONTINUE: u32 = 1;
const _: () =
    assert!(libc::SECCOMP_USER_NOTIF_FLAG_CONTINUE == USER_NOTIF_FLAG_CONTINUE as libc::c_ulong);

/// Bound on the audit hand-off queue. A block is always enforced; when the
/// queue is full (a slow/stuck Sidecar consumer) the audit report is dropped
/// rather than allowed to stall enforcement.
const AUDIT_QUEUE_DEPTH: usize = 128;

// AUDIT_ARCH_* and the `connect` syscall number for the targets OpenFirma
// supports. The filter matches the native arch only; a `connect(2)` issued via
// a foreign ABI (e.g. i386/x32 compat on x86_64) is NOT trapped and reaches
// loopback. This is an accepted V1 bypass: the private network namespace is the
// real boundary and this guard is defense in depth on top of it. Closing it
// would need per-arch `sockaddr` parsing (i386 routes connect through
// `socketcall`) and risks breaking legitimate compat syscalls — out of scope.
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
/// read megabytes from the agent's address space.
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
/// destinations pass only when the port matches one of Firma's own endpoints.
///
/// Matching is **port-only**, not address-scoped: any loopback IP on a
/// sanctioned port passes (e.g. `127.0.0.5:18080`), not just the exact bridge
/// address. The agent picks the loopback IP its resolver returns for the proxy
/// (`127.0.0.1` vs `::1`), so pinning a single address would spuriously block
/// legitimate proxy traffic. The private network namespace is the real
/// boundary; this guard is defense in depth plus an audit trail on top of it.
fn classify(addr: SocketAddr, allow_ports: &[u16]) -> Verdict {
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
fn parse_sockaddr(bytes: &[u8]) -> Option<SocketAddr> {
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

// ── remote memory reader (process_vm_readv) ─────────────────────────────────

/// Reads `len` bytes at virtual address `addr` from process `pid` via
/// `process_vm_readv(2)`. Used to recover the `sockaddr` a `connect(2)` points
/// at.
///
/// `len` is capped at [`MAX_SOCKADDR_LEN`] *before* allocation so an
/// agent-controlled `addrlen` cannot force a large allocation. It can fail
/// (process gone, permission denied under an aggressive ptrace scope, or a short
/// read that does not cover all `len` bytes); callers fail closed for unreadable
/// non-null sockaddrs because the agent controls its own memory permissions.
fn read_remote_mem(pid: u32, addr: u64, len: usize) -> io::Result<Vec<u8>> {
    let len = len.min(MAX_SOCKADDR_LEN);
    let mut buf = vec![0_u8; len];
    let pid = i32::try_from(pid).map_err(|_| io::Error::other("pid out of range"))?;
    let base = usize::try_from(addr).map_err(|_| io::Error::other("address out of range"))?;
    let mut local_iov = [IoSliceMut::new(&mut buf)];
    let remote_iov = [nix::sys::uio::RemoteIoVec { base, len }];
    let n = nix::sys::uio::process_vm_readv(Pid::from_raw(pid), &mut local_iov, &remote_iov)
        .map_err(io::Error::from)?;
    // process_vm_readv may return a short count (e.g. sockaddr straddling a page
    // boundary with the second page unmapped). A partial read would leave the
    // tail zero-filled, misclassifying a loopback sockaddr as 0.0.0.0. Fail
    // closed: the caller treats an error as an unreadable sockaddr and blocks.
    if n != len {
        return Err(io::Error::other("short process_vm_readv"));
    }
    Ok(buf)
}

// ── in-jail listener probe (/proc/<pid>/net) ────────────────────────────────

/// TCP `st` value for `TCP_LISTEN`, as it appears (hex, upper-case) in
/// `/proc/<pid>/net/{tcp,tcp6}`.
const PROC_NET_TCP_LISTEN: &str = "0A";
/// UDP `st` value for a bound socket in `/proc/<pid>/net/{udp,udp6}`.
const PROC_NET_UDP_BOUND: &str = "07";

/// Reads the set of local ports with a listening TCP socket or a bound UDP
/// socket in the network namespace of process `pid`, by parsing
/// `/proc/<pid>/net/{tcp,tcp6,udp,udp6}`.
///
/// The supervisor runs on the host in the initial pid namespace, so `pid` (the
/// `seccomp_notif.pid`, valid there — the same pid the sockaddr is read from via
/// `process_vm_readv`) resolves to the agent's `/proc` entry, and
/// `/proc/<pid>/net/*` reflects the agent's private network namespace.
///
/// Used to distinguish a loopback `connect(2)` that targets a listener the agent
/// started inside its own jail (allowed) from one that does not (blocked).
/// Matching is port-only, consistent with [`classify`]: the connect's protocol
/// is not knowable from the `sockaddr`, so both TCP-listen and UDP-bound ports
/// are collected to avoid a false block on an in-jail UDP service.
///
/// An absent `tcp6`/`udp6` (IPv6 disabled) is treated as empty; any other read
/// error propagates so the caller can fail closed.
fn netns_local_ports(pid: u32) -> io::Result<BTreeSet<u16>> {
    let mut ports = BTreeSet::new();
    for (leaf, listen_state) in [
        ("tcp", PROC_NET_TCP_LISTEN),
        ("tcp6", PROC_NET_TCP_LISTEN),
        ("udp", PROC_NET_UDP_BOUND),
        ("udp6", PROC_NET_UDP_BOUND),
    ] {
        let path = format!("/proc/{pid}/net/{leaf}");
        let content = match std::fs::read_to_string(&path) {
            Ok(content) => content,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        collect_listening_ports(&content, listen_state, &mut ports);
    }
    Ok(ports)
}

/// Parses one `/proc/<pid>/net/{tcp,tcp6,udp,udp6}` table, inserting the local
/// port of every row whose socket state equals `listen_state`.
///
/// Row layout is `sl local_address rem_address st ...`, where `local_address`
/// is `HEXIP:HEXPORT` and `st` is the hex socket state. The first line is the
/// column header (`local_address` in the state column) and simply fails the
/// state match, so it is skipped without special-casing.
fn collect_listening_ports(table: &str, listen_state: &str, ports: &mut BTreeSet<u16>) {
    for line in table.lines() {
        let mut fields = line.split_whitespace();
        // token[1] = local_address, then token[3] = state (two positions on).
        let local = fields.nth(1);
        let state = fields.nth(1);
        let (Some(local), Some(state)) = (local, state) else {
            continue;
        };
        if state != listen_state {
            continue;
        }
        let Some(port_hex) = local.rsplit(':').next() else {
            continue;
        };
        if let Ok(port) = u16::from_str_radix(port_hex, 16) {
            ports.insert(port);
        }
    }
}

// ── BPF program ─────────────────────────────────────────────────────────────

/// The cBPF program: notify on `connect` for the native arch, allow everything
/// else (including foreign-arch syscalls).
const CONNECT_NOTIFY_PROG: [libc::sock_filter; 6] = [
    // 0: load arch
    libc::sock_filter {
        code: BPF_LD_W_ABS,
        jt: 0,
        jf: 0,
        k: SECCOMP_DATA_ARCH_OFFSET,
    },
    // 1: if arch != native -> allow (skip 3 to idx5)
    libc::sock_filter {
        code: BPF_JMP_JEQ_K,
        jt: 0,
        jf: 3,
        k: NATIVE_AUDIT_ARCH,
    },
    // 2: load syscall nr
    libc::sock_filter {
        code: BPF_LD_W_ABS,
        jt: 0,
        jf: 0,
        k: SECCOMP_DATA_NR_OFFSET,
    },
    // 3: if nr != connect -> allow (skip 1 to idx5)
    libc::sock_filter {
        code: BPF_JMP_JEQ_K,
        jt: 0,
        jf: 1,
        k: SYS_CONNECT_NR,
    },
    // 4: connect -> notify the supervisor
    libc::sock_filter {
        code: BPF_RET_K,
        jt: 0,
        jf: 0,
        k: libc::SECCOMP_RET_USER_NOTIF,
    },
    // 5: allow
    libc::sock_filter {
        code: BPF_RET_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_ALLOW,
    },
];

// ── seccomp install (FFI) ───────────────────────────────────────────────────

/// Installs the connect-notify filter on the current process and returns the
/// notification listener fd.
fn install_connect_notifier() -> io::Result<OwnedFd> {
    // Unprivileged seccomp requires no-new-privs.
    nix::sys::prctl::set_no_new_privs().map_err(io::Error::from)?;

    // Local mutable copy: `sock_fprog.filter` is `*mut`, though the kernel only
    // reads the program during `SYS_seccomp`.
    let mut program = CONNECT_NOTIFY_PROG;
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

const fn ioc(dir: u64, nr: u64, size: usize) -> libc::Ioctl {
    ((dir << 30) | (SECCOMP_IOC_MAGIC << 8) | nr | ((size as u64) << 16)) as libc::Ioctl
}

fn notif_recv_req() -> libc::Ioctl {
    ioc(
        IOC_READ | IOC_WRITE,
        0,
        std::mem::size_of::<libc::seccomp_notif>(),
    )
}
fn notif_send_req() -> libc::Ioctl {
    ioc(
        IOC_READ | IOC_WRITE,
        1,
        std::mem::size_of::<libc::seccomp_notif_resp>(),
    )
}
fn notif_id_valid_req() -> libc::Ioctl {
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
/// caller (the `__egress-guarded-run` subcommand) maps the error to a
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
    pub(crate) socket_path: PathBuf,
    /// Session and agent identity stamped onto each message.
    pub(crate) session_id: String,
    pub(crate) agent_id: AgentId,
}

/// Inputs to [`start`].
#[derive(Debug, Clone)]
pub struct SupervisorConfig {
    /// Unix socket the in-sandbox installer connects to, to hand over the
    /// listener fd. Must be reachable from inside the sandbox (bind-mounted).
    pub(crate) socket_path: PathBuf,
    /// Loopback ports the agent may still reach (proxy bridge, DNS stub).
    pub(crate) allow_ports: Vec<u16>,
    /// Optional sink for signed audit reports. When `None` (e.g. an external
    /// Sidecar whose env we do not control), blocks are still enforced but only
    /// logged locally.
    pub(crate) report: Option<AuditChannel>,
}

/// Live handle to a running guard supervisor. Dropping it stops the supervisor
/// thread and removes the control socket.
pub struct EgressGuardHandle {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    socket_path: PathBuf,
}

impl EgressGuardHandle {
    #[must_use]
    pub(crate) fn socket_path(&self) -> &Path {
        &self.socket_path
    }
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
pub(crate) fn start(config: SupervisorConfig) -> Result<EgressGuardHandle, RunError> {
    if let Some(parent) = config.socket_path.parent() {
        firma_fs::create_private_dir_all(parent).map_err(|error| RunError::Backend {
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

    // Audit delivery runs on its own thread so a slow or stuck Sidecar consumer
    // can never block the notify loop (which would hang the agent's next
    // connect, allowed connects included). Enforcement stays synchronous.
    // Dropping `audit` at scope end closes the channel and joins the worker.
    let audit = config.report.clone().and_then(AuditSink::try_new);
    notify_loop(listener_fd.as_raw_fd(), config, stop, audit.as_ref());
}

/// The bounded sender the notify loop feeds and the delivery thread's join
/// handle, kept together so [`AuditSink`]'s `Drop` can move both out.
struct AuditInner {
    tx: SyncSender<SocketAddr>,
    handle: JoinHandle<()>,
}

/// Sink for blocked-connection audit reports, backed by a detached delivery
/// thread. Reports are handed off with [`Self::send`] (non-blocking); dropping
/// the sink closes the channel and joins the thread.
///
/// The inner is `Option` only so `Drop` can `take` it and move `tx`/`handle`
/// out of `&mut self` to enforce close-then-join ordering.
struct AuditSink {
    inner: Option<AuditInner>,
    /// Count of reports dropped because the worker's queue was full. Blocks are
    /// always enforced; only the audit report is lost. Surfaced once at Drop so
    /// a burst (e.g. a loopback port scan) is visible instead of silent.
    dropped: AtomicU64,
}

impl AuditSink {
    /// Creates a sink, spawning its delivery thread. On spawn failure returns
    /// `None`; the guard still enforces blocks, just without audit.
    fn try_new(channel: AuditChannel) -> Option<Self> {
        let (tx, rx) = sync_channel::<SocketAddr>(AUDIT_QUEUE_DEPTH);
        match std::thread::Builder::new()
            .name("firma-egress-audit".to_string())
            .spawn(move || {
                while let Ok(addr) = rx.recv() {
                    Self::report_event(&channel, addr);
                }
            }) {
            Ok(handle) => Some(Self {
                inner: Some(AuditInner { tx, handle }),
                dropped: AtomicU64::new(0),
            }),
            Err(error) => {
                tracing::warn!(
                    %error,
                    "egress guard: failed to spawn audit worker; blocks enforced without audit"
                );
                None
            }
        }
    }

    /// Non-blocking hand-off of a blocked destination. Drops the report rather
    /// than stall the notify loop if the worker's queue is full.
    fn send(&self, addr: SocketAddr) {
        if let Some(inner) = &self.inner
            && inner.tx.try_send(addr).is_err()
        {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Best-effort: forward a blocked attempt to the Sidecar over the `firma run`
    /// audit channel as a newline-delimited JSON [`RunAuditMessage`].
    fn report_event(channel: &AuditChannel, addr: SocketAddr) {
        let message = RunAuditMessage {
            session_id: channel.session_id.clone(),
            agent_id: channel.agent_id,
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
                // Bound the write so a stuck consumer cannot wedge the audit worker
                // indefinitely. Enforcement is already off this thread.
                let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
                if let Err(error) = stream.write_all(line.as_bytes()) {
                    tracing::debug!(%error, "egress guard: failed to write audit message");
                }
            }
            Err(error) => {
                tracing::debug!(%error, "egress guard: run-audit socket unreachable");
            }
        }
    }
}

impl Drop for AuditSink {
    fn drop(&mut self) {
        let dropped = self.dropped.load(Ordering::Relaxed);
        if dropped > 0 {
            tracing::warn!(
                dropped,
                "egress guard: audit queue overflowed; some loopback blocks were \
                 enforced but not audited (enforcement is never affected)"
            );
        }
        if let Some(AuditInner { tx, handle }) = self.inner.take() {
            drop(tx); // close the channel so the worker observes disconnect
            let _ = handle.join();
        }
    }
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
fn notify_loop(
    notify_fd: RawFd,
    config: &SupervisorConfig,
    stop: &AtomicBool,
    audit: Option<&AuditSink>,
) {
    // Reused across iterations; `notif_recv` re-zeroes it before every recv.
    let mut req: libc::seccomp_notif = unsafe { std::mem::zeroed() };
    while !stop.load(Ordering::SeqCst) {
        if !wait_readable(notify_fd, Duration::from_millis(200)) {
            continue;
        }
        match notif_recv(notify_fd, &mut req) {
            Ok(()) => handle_notification(notify_fd, &req, config, audit),
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
fn handle_notification(
    notify_fd: RawFd,
    req: &libc::seccomp_notif,
    config: &SupervisorConfig,
    audit: Option<&AuditSink>,
) {
    let verdict = classify_notification(req, &config.allow_ports);
    match verdict {
        NotifOutcome::Allow => {
            let resp = libc::seccomp_notif_resp {
                id: req.id,
                val: 0,
                error: 0,
                flags: USER_NOTIF_FLAG_CONTINUE,
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
            if let Some(addr) = addr {
                tracing::warn!(dst = %addr, "blocked agent connection to loopback");
                if let Some(audit) = audit {
                    audit.send(addr);
                }
            } else {
                tracing::warn!("blocked agent connection because sockaddr could not be read");
            }
        }
    }
}

enum NotifOutcome {
    Allow,
    Block(Option<SocketAddr>),
}

/// Reads and classifies the destination of a `connect` notification.
///
/// A non-null sockaddr pointer that cannot be read resolves to `Block`: an
/// agent can deliberately make its memory unreadable to the host supervisor, so
/// continuing would create a loopback-bypass primitive. Non-IP or malformed
/// sockaddrs still resolve to `Allow` so `AF_UNIX` and ordinary kernel validation
/// paths are not governed by this loopback guard.
///
/// A loopback destination on a non-sanctioned port is allowed only when the
/// agent's own network namespace has a listener on that port (a service the
/// agent started inside its jail, e.g. a test server); otherwise it is blocked.
/// An unreadable `/proc/<pid>/net` table fails closed to `Block`.
fn classify_notification(req: &libc::seccomp_notif, allow_ports: &[u16]) -> NotifOutcome {
    // connect(fd, sockaddr_ptr, addrlen): args[1] = pointer, args[2] = len.
    let addr_ptr = req.data.args[1];
    let addr_len = usize::try_from(req.data.args[2]).unwrap_or(0);
    if addr_ptr == 0 || addr_len < 2 {
        return NotifOutcome::Allow;
    }
    let Ok(bytes) = read_remote_mem(req.pid, addr_ptr, addr_len) else {
        return NotifOutcome::Block(None);
    };
    let Some(addr) = parse_sockaddr(&bytes) else {
        return NotifOutcome::Allow;
    };
    match classify(addr, allow_ports) {
        Verdict::Allow => NotifOutcome::Allow,
        // Not a sanctioned Firma endpoint. Allow only if the agent's own network
        // namespace has a listener on this port (a service it started inside its
        // jail); otherwise block and audit.
        Verdict::Block => match netns_local_ports(req.pid) {
            Ok(ports) if ports.contains(&addr.port()) => {
                tracing::debug!(dst = %addr, "allowing loopback connect to in-jail listener");
                NotifOutcome::Allow
            }
            Ok(_) => NotifOutcome::Block(Some(addr)),
            Err(error) => {
                // Fail closed: an unreadable /proc netns table must not open a
                // loopback bypass.
                tracing::debug!(%error, dst = %addr, "netns listener probe failed; blocking");
                NotifOutcome::Block(Some(addr))
            }
        },
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
        let prog = CONNECT_NOTIFY_PROG;
        assert_eq!(prog.len(), 6);
        assert_eq!(prog[4].k, libc::SECCOMP_RET_USER_NOTIF);
        assert_eq!(prog[5].k, SECCOMP_RET_ALLOW);
        assert_eq!(prog[3].k, SYS_CONNECT_NR);
    }

    // ── in-jail listener probe ──────────────────────────────────────────────

    #[test]
    fn collect_listening_ports_keeps_tcp_listen_only() {
        // Header + one LISTEN (0A) on 127.0.0.1:53 + one ESTABLISHED (01) that
        // must be ignored.
        let table = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   101        0 12345 1 0000 100 0 0 10 0
   1: 0100007F:1F90 0100007F:C000 01 00000000:00000000 00:00000000 00000000  1000        0 67890 1 0000 20 4 30 10 -1
";
        let mut ports = BTreeSet::new();
        collect_listening_ports(table, PROC_NET_TCP_LISTEN, &mut ports);
        assert!(ports.contains(&0x0035), "LISTEN row port must be collected");
        assert!(
            !ports.contains(&0x1F90),
            "ESTABLISHED row must not be collected"
        );
    }

    #[test]
    fn collect_listening_ports_parses_ipv6_rows() {
        // tcp6 carries a 32-hex-char local address; only the port after ':'
        // matters.
        let table = "\
  sl  local_address                         remote_address                        st
   0: 00000000000000000000000001000000:8000 00000000000000000000000000000000:0000 0A
";
        let mut ports = BTreeSet::new();
        collect_listening_ports(table, PROC_NET_TCP_LISTEN, &mut ports);
        assert!(ports.contains(&0x8000));
    }

    #[test]
    fn collect_listening_ports_matches_udp_bound_state() {
        let table = "\
  sl  local_address rem_address   st
   0: 0100007F:0035 00000000:0000 07
";
        let mut tcp = BTreeSet::new();
        collect_listening_ports(table, PROC_NET_TCP_LISTEN, &mut tcp);
        assert!(tcp.is_empty(), "UDP-bound row must not match TCP_LISTEN");

        let mut udp = BTreeSet::new();
        collect_listening_ports(table, PROC_NET_UDP_BOUND, &mut udp);
        assert!(udp.contains(&0x0035), "UDP-bound row must match UDP state");
    }

    #[test]
    fn collect_listening_ports_skips_header_and_garbage() {
        let mut ports = BTreeSet::new();
        collect_listening_ports(
            "sl local_address rem_address st\n",
            PROC_NET_TCP_LISTEN,
            &mut ports,
        );
        collect_listening_ports("garbage\n\n   \n", PROC_NET_TCP_LISTEN, &mut ports);
        assert!(ports.is_empty());
    }

    /// `netns_local_ports` reads the caller's own `/proc/self/net/tcp`, so a
    /// listener bound in this process must appear in the returned set.
    #[test]
    fn netns_local_ports_includes_a_bound_listener() {
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let ports = netns_local_ports(std::process::id()).expect("read own netns ports");
        assert!(
            ports.contains(&port),
            "own listening port {port} must be present in {ports:?}"
        );
    }

    /// `read_remote_mem` recovers bytes from a live process. Reading our own
    /// process exercises the `process_vm_readv` path without a child.
    #[test]
    fn read_remote_mem_reads_own_memory() {
        let payload = b"firma-egress-guard-remote-read".to_vec();
        let out = read_remote_mem(std::process::id(), payload.as_ptr() as u64, payload.len())
            .expect("read own memory");
        assert_eq!(out, payload);
    }

    /// The requested length is capped at `MAX_SOCKADDR_LEN` before the read, so
    /// an agent-controlled `addrlen` cannot force a large allocation or read.
    #[test]
    fn read_remote_mem_caps_length() {
        let backing = vec![0xAB_u8; MAX_SOCKADDR_LEN * 4];
        let out = read_remote_mem(std::process::id(), backing.as_ptr() as u64, backing.len())
            .expect("read own memory");
        assert_eq!(out.len(), MAX_SOCKADDR_LEN);
    }

    /// Builds a zeroed `connect` notification whose `sockaddr` pointer/len point
    /// at a buffer in this process, so `classify_notification` can resolve it via
    /// `read_remote_mem` against our own pid.
    fn notif_pointing_at(buf: &[u8]) -> libc::seccomp_notif {
        let mut req: libc::seccomp_notif = unsafe { std::mem::zeroed() };
        req.pid = std::process::id();
        req.data.args[1] = buf.as_ptr() as u64;
        req.data.args[2] = buf.len() as u64;
        req
    }

    fn v4_sockaddr(ip: [u8; 4], port: u16) -> Vec<u8> {
        let mut bytes = vec![0_u8; 16];
        bytes[0..2].copy_from_slice(&AF_INET.to_ne_bytes());
        bytes[2..4].copy_from_slice(&port.to_be_bytes());
        bytes[4..8].copy_from_slice(&ip);
        bytes
    }

    #[test]
    fn classify_notification_blocks_unsanctioned_loopback() {
        let addr = v4_sockaddr([127, 0, 0, 1], 0);
        let req = notif_pointing_at(&addr);
        match classify_notification(&req, &allow()) {
            NotifOutcome::Block(Some(got)) => {
                assert_eq!(got, "127.0.0.1:0".parse().unwrap());
            }
            NotifOutcome::Allow | NotifOutcome::Block(None) => {
                panic!("expected Block for unsanctioned loopback");
            }
        }
    }

    #[test]
    fn classify_notification_allows_sanctioned_loopback() {
        let addr = v4_sockaddr([127, 0, 0, 1], PROXY);
        let req = notif_pointing_at(&addr);
        assert!(matches!(
            classify_notification(&req, &allow()),
            NotifOutcome::Allow
        ));
    }

    #[test]
    fn classify_notification_allows_external() {
        let addr = v4_sockaddr([93, 184, 216, 34], 443);
        let req = notif_pointing_at(&addr);
        assert!(matches!(
            classify_notification(&req, &allow()),
            NotifOutcome::Allow
        ));
    }

    #[test]
    fn classify_notification_allows_null_or_short_addr() {
        // Null pointer -> allow (nothing to classify).
        let mut req: libc::seccomp_notif = unsafe { std::mem::zeroed() };
        req.pid = std::process::id();
        req.data.args[1] = 0;
        req.data.args[2] = 16;
        assert!(matches!(
            classify_notification(&req, &allow()),
            NotifOutcome::Allow
        ));

        // Non-null but too short to hold a `sa_family` -> allow.
        let addr = v4_sockaddr([127, 0, 0, 1], 9000);
        let mut short = notif_pointing_at(&addr);
        short.data.args[2] = 1;
        assert!(matches!(
            classify_notification(&short, &allow()),
            NotifOutcome::Allow
        ));
    }

    #[test]
    fn classify_notification_blocks_unreadable_sockaddr() {
        let mut req: libc::seccomp_notif = unsafe { std::mem::zeroed() };
        req.pid = std::process::id();
        req.data.args[1] = 1;
        req.data.args[2] = 16;

        assert!(matches!(
            classify_notification(&req, &allow()),
            NotifOutcome::Block(None)
        ));
    }

    /// The seccomp-notify ioctl request numbers are distinct and non-zero so the
    /// three ioctls address different commands.
    #[test]
    fn notif_ioctl_requests_are_distinct() {
        let recv = notif_recv_req();
        let send = notif_send_req();
        let valid = notif_id_valid_req();
        assert_ne!(recv, 0);
        assert_ne!(recv, send);
        assert_ne!(send, valid);
        assert_ne!(recv, valid);
    }

    /// `AuditSink` forwards a blocked destination to the run-audit socket as a
    /// newline-delimited `RunAuditMessage`. Covers `try_new`, `send`,
    /// `report_event`, and the close-then-join `Drop`.
    #[test]
    fn audit_sink_forwards_blocked_destination() {
        use std::io::Read as _;

        let dir = std::env::temp_dir().join(format!("firma-egress-audit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let socket_path = dir.join("run-audit.sock");
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path).expect("bind audit socket");

        let (tx, rx) = std::sync::mpsc::channel();
        let accept = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut line = String::new();
                let _ = stream.read_to_string(&mut line);
                let _ = tx.send(line);
            }
        });

        let channel = AuditChannel {
            socket_path: socket_path.clone(),
            session_id: "sess-1".to_string(),
            agent_id: "agt_01j0000000e008000000000001"
                .parse()
                .expect("valid agent ID"),
        };
        let sink = AuditSink::try_new(channel).expect("spawn audit sink");
        sink.send("127.0.0.1:9000".parse().unwrap());
        drop(sink); // closes channel, joins worker after the send is delivered

        accept.join().expect("accept thread");
        let line = rx.recv().expect("audit line delivered");
        assert!(
            line.ends_with('\n'),
            "line must be newline-delimited: {line:?}"
        );
        let value: serde_json::Value = serde_json::from_str(line.trim()).expect("valid JSON");
        assert_eq!(value["session_id"], "sess-1");
        assert_eq!(value["agent_id"], "agt_01j0000000e008000000000001");
        assert_eq!(value["event"]["kind"], "loopback_blocked");
        assert_eq!(value["event"]["dst_ip"], "127.0.0.1");
        assert_eq!(value["event"]["dst_port"], 9000);

        let _ = std::fs::remove_file(&socket_path);
        let _ = std::fs::remove_dir(&dir);
    }

    // ── is_loopback / classify edges ────────────────────────────────────────

    #[test]
    fn ipv4_mapped_non_loopback_allowed() {
        // ::ffff:93.184.216.34 maps a public v4 -> not loopback -> allowed.
        let addr: SocketAddr = "[::ffff:93.184.216.34]:443".parse().unwrap();
        assert_eq!(classify(addr, &allow()), Verdict::Allow);
    }

    #[test]
    fn unspecified_addresses_allowed() {
        let v4: SocketAddr = "0.0.0.0:9000".parse().unwrap();
        let v6: SocketAddr = "[::]:9000".parse().unwrap();
        assert_eq!(classify(v4, &allow()), Verdict::Allow);
        assert_eq!(classify(v6, &allow()), Verdict::Allow);
    }

    #[test]
    fn loopback_to_dns_port_passes() {
        let addr: SocketAddr = "127.0.0.1:53".parse().unwrap();
        assert_eq!(classify(addr, &allow()), Verdict::Allow);
    }

    #[test]
    fn empty_allow_list_blocks_all_loopback() {
        let addr: SocketAddr = "127.0.0.1:18080".parse().unwrap();
        assert_eq!(classify(addr, &[]), Verdict::Block);
    }

    #[test]
    fn external_on_unsanctioned_port_allowed() {
        // The guard governs only loopback; a public IP on any port is allowed.
        let addr: SocketAddr = "93.184.216.34:9000".parse().unwrap();
        assert_eq!(classify(addr, &allow()), Verdict::Allow);
    }

    // ── parse_sockaddr boundaries ───────────────────────────────────────────

    #[test]
    fn parse_ipv4_len_boundary() {
        let full = v4_sockaddr([127, 0, 0, 1], 80);
        assert!(parse_sockaddr(&full[..8]).is_some());
        assert!(parse_sockaddr(&full[..7]).is_none());
    }

    #[test]
    fn parse_ipv6_len_boundary() {
        let addr = v6_sockaddr(Ipv6Addr::LOCALHOST, 53);
        assert!(parse_sockaddr(&addr[..24]).is_some());
        assert!(parse_sockaddr(&addr[..23]).is_none());
    }

    #[test]
    fn parse_empty_is_none() {
        assert!(parse_sockaddr(&[]).is_none());
    }

    #[test]
    fn parse_ipv4_port_is_big_endian() {
        let mut bytes = v4_sockaddr([127, 0, 0, 1], 0);
        bytes[2] = 0x12;
        bytes[3] = 0x34;
        let addr = parse_sockaddr(&bytes).expect("parse");
        assert_eq!(addr.port(), 0x1234);
    }

    #[test]
    fn parse_ipv4_mapped_loopback_then_classify_blocks() {
        // An AF_INET6 sockaddr carrying ::ffff:127.0.0.1 parses as V6 and
        // classifies as loopback, so an unsanctioned port is blocked.
        let mapped = Ipv4Addr::LOCALHOST.to_ipv6_mapped();
        let bytes = v6_sockaddr(mapped, 6379);
        let addr = parse_sockaddr(&bytes).expect("parse");
        assert!(addr.is_ipv6());
        assert_eq!(classify(addr, &allow()), Verdict::Block);
    }

    // ── classify_notification: ipv6, AF_UNIX, sanctioned DNS ────────────────

    fn v6_sockaddr(ip: Ipv6Addr, port: u16) -> Vec<u8> {
        let mut bytes = vec![0_u8; 28];
        bytes[0..2].copy_from_slice(&AF_INET6.to_ne_bytes());
        bytes[2..4].copy_from_slice(&port.to_be_bytes());
        // sockaddr_in6: family(2) port(2) flowinfo(4) addr(16)
        bytes[8..24].copy_from_slice(&ip.octets());
        bytes
    }

    #[test]
    fn classify_notification_blocks_ipv6_loopback() {
        let addr = v6_sockaddr(Ipv6Addr::LOCALHOST, 6379);
        let req = notif_pointing_at(&addr);
        match classify_notification(&req, &allow()) {
            NotifOutcome::Block(Some(got)) => assert_eq!(got, "[::1]:6379".parse().unwrap()),
            NotifOutcome::Allow | NotifOutcome::Block(None) => {
                panic!("expected Block for ipv6 loopback");
            }
        }
    }

    #[test]
    fn classify_notification_allows_af_unix() {
        // AF_UNIX (1) is not an IP family; parse yields None -> Allow, so the
        // loopback guard never governs unix-domain connects.
        let mut buf = vec![0_u8; 16];
        buf[0..2].copy_from_slice(&1_u16.to_ne_bytes());
        let req = notif_pointing_at(&buf);
        assert!(matches!(
            classify_notification(&req, &allow()),
            NotifOutcome::Allow
        ));
    }

    #[test]
    fn classify_notification_allows_sanctioned_dns_port() {
        let addr = v4_sockaddr([127, 0, 0, 1], DNS);
        let req = notif_pointing_at(&addr);
        assert!(matches!(
            classify_notification(&req, &allow()),
            NotifOutcome::Allow
        ));
    }

    // ── BPF routing ─────────────────────────────────────────────────────────

    #[test]
    fn bpf_program_routes_arch_and_nr() {
        let p = CONNECT_NOTIFY_PROG;
        // Load arch, then on a foreign arch jump-false past both nr checks to the
        // final allow (jf = 3 -> index 5).
        assert_eq!(p[0].k, SECCOMP_DATA_ARCH_OFFSET);
        assert_eq!(p[1].k, NATIVE_AUDIT_ARCH);
        assert_eq!(p[1].jf, 3);
        // Load nr, then on any non-connect syscall jump-false to allow (jf = 1).
        assert_eq!(p[2].k, SECCOMP_DATA_NR_OFFSET);
        assert_eq!(p[3].jf, 1);
    }

    // ── SCM_RIGHTS fd transfer ──────────────────────────────────────────────

    #[test]
    fn listener_fd_roundtrip_transfers_open_file() {
        use std::io::{Read as _, Write as _};

        let dir = std::env::temp_dir().join(format!("firma-fd-xfer-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("marker");
        {
            let mut f = std::fs::File::create(&path).expect("create");
            f.write_all(b"firma-fd-marker").expect("write");
        }
        let orig = std::fs::File::open(&path).expect("open");

        let (a, b) = UnixStream::pair().expect("socketpair");
        send_listener_fd(&a, orig.as_raw_fd()).expect("send fd");
        let received = recv_listener_fd(&b).expect("recv fd");

        // The received fd is the same open file description; reading it yields the
        // bytes written through the original path.
        let mut f = std::fs::File::from(received);
        let mut got = String::new();
        f.read_to_string(&mut got).expect("read via received fd");
        assert_eq!(got, "firma-fd-marker");

        drop(orig);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn recv_listener_fd_without_scm_rights_errors() {
        let (a, b) = UnixStream::pair().expect("socketpair");
        // Send a plain byte with no SCM_RIGHTS control message.
        let payload = [0_u8; 1];
        let iov = [IoSlice::new(&payload)];
        let cmsgs: &[ControlMessage] = &[];
        sendmsg::<()>(a.as_raw_fd(), &iov, cmsgs, MsgFlags::empty(), None).expect("sendmsg");
        let err = recv_listener_fd(&b).expect_err("expected error when no fd is sent");
        assert!(
            err.to_string().contains("no fd received"),
            "unexpected error: {err}"
        );
    }

    // ── supervisor lifecycle ────────────────────────────────────────────────

    #[test]
    fn start_binds_socket_and_drop_removes_it() {
        let dir = std::env::temp_dir().join(format!("firma-egress-start-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let socket_path = dir.join("guard.sock");

        let handle = start(SupervisorConfig {
            socket_path: socket_path.clone(),
            allow_ports: allow(),
            report: None,
        })
        .expect("start guard");

        assert_eq!(handle.socket_path(), socket_path);
        assert!(socket_path.exists(), "control socket should be bound");

        drop(handle); // signals stop, joins the supervisor thread, removes socket
        assert!(!socket_path.exists(), "socket removed on drop");

        let _ = std::fs::remove_dir(&dir);
    }

    // ── installer error paths (no filter installed) ─────────────────────────

    #[test]
    fn install_and_exec_rejects_empty_argv() {
        let err = install_and_exec(Path::new("/definitely/missing.sock"), &[])
            .expect_err("empty argv must error");
        assert!(matches!(err, RunError::Internal(_)), "got {err:?}");
    }

    #[test]
    fn install_and_exec_errors_on_unreachable_supervisor() {
        // Fails at the AF_UNIX connect, before any seccomp filter is installed.
        let missing =
            std::env::temp_dir().join(format!("firma-missing-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&missing);
        let argv = vec!["/bin/true".to_string()];
        let err = install_and_exec(&missing, &argv).expect_err("unreachable socket must error");
        assert!(matches!(err, RunError::Internal(_)), "got {err:?}");
    }

    // ── notify ioctl wrappers reject a non-notify fd ────────────────────────

    #[test]
    fn notif_ioctls_error_on_non_notify_fd() {
        // A plain socket fd is not a seccomp notify fd; the ioctls must fail
        // rather than silently succeed.
        let (a, _b) = UnixStream::pair().expect("socketpair");
        let fd = a.as_raw_fd();
        let mut req: libc::seccomp_notif = unsafe { std::mem::zeroed() };
        assert!(notif_recv(fd, &mut req).is_err());
        let resp = libc::seccomp_notif_resp {
            id: 0,
            val: 0,
            error: 0,
            flags: 0,
        };
        assert!(notif_send(fd, &resp).is_err());
        assert!(!notif_id_is_valid(fd, 0));
    }

    // ── real seccomp round-trip ─────────────────────────────────────────────
    //
    // Installs a live connect-notify filter and drives an allow and a block
    // through the full supervisor path (install -> fd hand-off -> notify loop ->
    // classify -> respond). nextest runs each test in its own process, so the
    // permanent filter cannot leak into other tests. The filter is installed on
    // this thread only (no TSYNC), so the supervisor thread stays unfiltered.

    #[test]
    fn guard_blocks_and_allows_real_connects() {
        use std::net::{TcpListener, TcpStream};

        // A real loopback listener the "agent" started inside its own netns. It
        // is deliberately NOT placed in allow_ports: the guard must allow the
        // connect purely because the port has an in-jail listener (Plan B).
        let allowed = TcpListener::bind("127.0.0.1:0").expect("bind allowed");
        let allowed_port = allowed.local_addr().expect("addr").port();
        // Reserve then release a port so nothing listens on it: a connect here
        // has no in-jail listener and no sanctioned port, so it must be blocked.
        let blocked_reservation = TcpListener::bind("127.0.0.1:0").expect("bind blocked");
        let blocked_port = blocked_reservation.local_addr().expect("addr").port();
        drop(blocked_reservation);

        let dir = std::env::temp_dir().join(format!("firma-egress-e2e-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let socket_path = dir.join("guard.sock");

        let handle = start(SupervisorConfig {
            socket_path: socket_path.clone(),
            // No sanctioned ports: the allow verdict is proven purely by the
            // in-jail listener probe.
            allow_ports: vec![],
            report: None,
        })
        .expect("start guard");

        // Mimic the in-sandbox installer: connect to the supervisor *before*
        // installing the filter (that AF_UNIX connect must not be trapped), then
        // install and hand over the listener fd.
        let stream = UnixStream::connect(&socket_path).expect("connect supervisor");
        let Ok(listener_fd) = install_connect_notifier() else {
            // Environment without unprivileged user-notify: skip rather than hang.
            eprintln!("skipping guard round-trip: seccomp user-notify unavailable");
            return;
        };
        send_listener_fd(&stream, listener_fd.as_raw_fd()).expect("send fd");
        drop(listener_fd); // supervisor holds its own copy
        drop(stream);

        // From here this thread's connect(2) is trapped and serviced by the
        // supervisor thread. Bound each connect so a servicing failure times out
        // instead of hanging the test forever.
        let allow_addr = SocketAddr::from(([127, 0, 0, 1], allowed_port));
        let block_addr = SocketAddr::from(([127, 0, 0, 1], blocked_port));

        let allowed_res = TcpStream::connect_timeout(&allow_addr, Duration::from_secs(5));
        assert!(
            allowed_res.is_ok(),
            "in-jail listener port must connect (allow-continue): {allowed_res:?}"
        );

        let blocked_res = TcpStream::connect_timeout(&block_addr, Duration::from_secs(5));
        match blocked_res {
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {}
            other => panic!("unsanctioned loopback must be blocked with EACCES, got {other:?}"),
        }

        drop(handle);
        let _ = std::fs::remove_file(&socket_path);
        let _ = std::fs::remove_dir(&dir);
    }
}
