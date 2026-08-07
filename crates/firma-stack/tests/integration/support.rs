#![cfg(unix)]

use std::path::Path;
use std::time::{Duration, Instant};

use firma_runtime_state::pidfile;
use nix::unistd::Pid;

pub struct ProcessGroupCleanup(Option<Pid>);

impl ProcessGroupCleanup {
    pub fn new(pid: u32) -> Self {
        Self(i32::try_from(pid).ok().map(Pid::from_raw))
    }

    pub fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for ProcessGroupCleanup {
    fn drop(&mut self) {
        if let Some(pid) = self.0 {
            let _ = nix::sys::signal::killpg(pid, nix::sys::signal::Signal::SIGKILL);
        }
    }
}

pub fn wait_for_pidfile(path: &Path) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(pid) = pidfile::read(path).expect("read process pidfile") {
            return pid.get();
        }
        assert!(Instant::now() < deadline, "{} missing", path.display());
        std::thread::sleep(Duration::from_millis(10));
    }
}

pub fn wait_for_file(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !path.exists() {
        assert!(Instant::now() < deadline, "{} missing", path.display());
        std::thread::sleep(Duration::from_millis(10));
    }
}
