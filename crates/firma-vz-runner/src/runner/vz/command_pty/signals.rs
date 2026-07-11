use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};

static HOST_SIGWINCH_COUNT: AtomicUsize = AtomicUsize::new(0);
static HOST_SIGINT_COUNT: AtomicUsize = AtomicUsize::new(0);
static HOST_SIGTERM_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Records a host SIGINT for the PTY control loop.
pub fn record_host_sigint() {
    HOST_SIGINT_COUNT.fetch_add(1, Ordering::SeqCst);
}

/// Returns the observed host SIGINT counter used by the PTY control loop.
pub fn host_sigint_count() -> usize {
    HOST_SIGINT_COUNT.load(Ordering::SeqCst)
}

/// Returns the observed host SIGTERM counter used by the VM stop loop.
pub fn host_sigterm_count() -> usize {
    HOST_SIGTERM_COUNT.load(Ordering::SeqCst)
}

/// Returns the observed host SIGWINCH counter used by the PTY control loop.
pub fn host_sigwinch_count() -> usize {
    HOST_SIGWINCH_COUNT.load(Ordering::SeqCst)
}

/// Installs the SIGTERM handler used for PTY control and VM shutdown.
pub fn install_sigterm_handler() -> io::Result<()> {
    let previous = unsafe {
        libc::signal(
            libc::SIGTERM,
            handle_host_sigterm as *const () as libc::sighandler_t,
        )
    };

    if previous == libc::SIG_ERR {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

/// Installs the SIGWINCH handler used for resize forwarding.
pub fn install_sigwinch_handler() -> io::Result<()> {
    let previous = unsafe {
        libc::signal(
            libc::SIGWINCH,
            handle_host_sigwinch as *const () as libc::sighandler_t,
        )
    };

    if previous == libc::SIG_ERR {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

/// Records a host SIGWINCH for the PTY control loop.
extern "C" fn handle_host_sigwinch(_: libc::c_int) {
    HOST_SIGWINCH_COUNT.fetch_add(1, Ordering::SeqCst);
}

/// Records a host SIGTERM for the PTY control loop and VM shutdown loop.
extern "C" fn handle_host_sigterm(_: libc::c_int) {
    HOST_SIGTERM_COUNT.fetch_add(1, Ordering::SeqCst);
}
