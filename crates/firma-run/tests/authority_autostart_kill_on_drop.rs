//! Spawn an Authority impostor that emits the contract and sleeps
//! indefinitely. Drop the supervisor and assert the child is reaped
//! within the grace window.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

#[cfg(unix)]
use std::time::{Duration, Instant};

#[cfg(unix)]
use firma_run::authority::{AuthoritySupervisor, SpawnRequest};

#[cfg(unix)]
#[test]
fn drop_reaps_child_within_grace() {
    use std::os::unix::fs::PermissionsExt as _;
    let tmp = tempfile::tempdir().expect("tempdir");
    let fake = tmp.path().join("fake-firma.sh");
    std::fs::write(
        &fake,
        "#!/usr/bin/env bash\n\
         case \"$1\" in\n\
           authority) shift; case \"$1\" in\n\
             generate-key) shift; touch \"$2\" \"$2.pub\";;\n\
             *)\n\
               echo 'firma_authority: config loaded policy_dir=\"/x\" listen_addr=\"[::1]:50051\"' >&2\n\
               echo 'firma_authority: policy bundle loaded policies=1' >&2\n\
               echo 'firma_authority: listening addr=\"[::1]:50051\"' >&2\n\
               echo 'firma_authority: authority ready' >&2\n\
               exec sleep 60;;\n\
           esac;;\n\
         esac\n",
    )
    .unwrap();
    let mut p = std::fs::metadata(&fake).unwrap().permissions();
    p.set_mode(0o755);
    std::fs::set_permissions(&fake, p).unwrap();

    let sup = AuthoritySupervisor::spawn(SpawnRequest {
        sandbox_id: &firma_run::identity::SandboxId::from("sb1"),
        agent_id: "agent",
        session_id: "sess",
        marker_dir: tmp.path().join("marker/authority"),
        profile_name: "developer",
        firma_exe: fake,
        startup_timeout: Duration::from_secs(5),
    })
    .expect("spawn ok");
    let pid = sup.pid();
    drop(sup);

    let deadline = Instant::now() + Duration::from_secs(7);
    while Instant::now() < deadline {
        match nix::sys::signal::kill(pid.as_nix_pid(), None) {
            Err(nix::errno::Errno::ESRCH) => return,
            _ => std::thread::sleep(Duration::from_millis(100)),
        }
    }
    panic!("child {pid} not reaped within 7s");
}
