//! Spawn a child that prints fewer than the contract lines and sleeps;
//! `AuthoritySupervisor::spawn` must return `AuthorityReadyTimeout`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

#[cfg(unix)]
#[test]
fn timeout_kills_child_and_returns_typed_error() {
    use firma_run::authority::{AuthoritySupervisor, SpawnRequest};
    use firma_run::error::RunError;
    use std::os::unix::fs::PermissionsExt as _;
    use std::time::Duration;

    let tmp = tempfile::tempdir().expect("tempdir");
    let fake = tmp.path().join("fake-firma.sh");
    std::fs::write(
        &fake,
        "#!/usr/bin/env bash\n\
         case \"$1\" in\n\
           authority) shift; case \"$1\" in\n\
             generate-key) shift; touch \"$2\" \"$2.pub\";;\n\
             *) echo 'incomplete' >&2; exec sleep 30;;\n\
           esac;;\n\
         esac\n",
    )
    .expect("write fake");
    let mut p = std::fs::metadata(&fake).unwrap().permissions();
    p.set_mode(0o755);
    std::fs::set_permissions(&fake, p).unwrap();

    let result = AuthoritySupervisor::spawn(SpawnRequest {
        sandbox_id: &firma_run::identity::SandboxId::from("sb1"),
        agent_id: "agent",
        session_id: "sess",
        marker_dir: tmp.path().join("marker/authority"),
        profile_name: "developer",
        firma_exe: fake,
        startup_timeout: Duration::from_millis(500),
    });
    let Err(err) = result else {
        panic!("must time out")
    };
    assert!(
        matches!(err, RunError::AuthorityReadyTimeout { .. }),
        "got {err:?}"
    );
}
