//! End-to-end: spawn impostor authority that emits the contract and
//! stays alive. Verify the marker dir, metadata.toml schema, and
//! `developer.cedar` content match Spec §5.1.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

#[cfg(unix)]
use std::time::Duration;

#[cfg(unix)]
use firma_run::authority::{AuthoritySupervisor, SpawnRequest};

#[cfg(unix)]
#[test]
fn marker_dir_layout_and_developer_cedar() {
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
               echo 'firma_authority: ready' >&2\n\
               exec sleep 60;;\n\
           esac;;\n\
         esac\n",
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    let mut p = std::fs::metadata(&fake).unwrap().permissions();
    p.set_mode(0o755);
    std::fs::set_permissions(&fake, p).unwrap();

    let marker = tmp.path().join("marker/authority");
    let sup = AuthoritySupervisor::spawn(SpawnRequest {
        sandbox_id: "sb1",
        agent_id: "agent",
        session_id: "sess",
        marker_dir: marker.clone(),
        profile_name: "developer",
        firma_exe: fake,
        startup_timeout: Duration::from_secs(5),
    })
    .expect("spawn ok");

    assert!(marker.join("authority.toml").is_file());
    assert!(marker.join("authority.pid").is_file());
    assert!(marker.join("metadata.toml").is_file());
    assert!(marker.join("policy_dir/developer.cedar").is_file());
    assert!(marker.join("keys/authority.key").is_file());

    let meta = std::fs::read_to_string(marker.join("metadata.toml")).unwrap();
    assert!(meta.contains("sandbox_id = \"sb1\""), "got: {meta}");
    assert!(meta.contains("profile = \"developer\""));
    assert!(meta.contains("listen_addr = \"[::1]:50051\""));

    let cedar = std::fs::read_to_string(marker.join("policy_dir/developer.cedar")).unwrap();
    assert!(cedar.contains("NOT INTENDED FOR PRODUCTION"));
    assert!(cedar.contains("forbid"));
    assert!(cedar.contains("firma monitor --only-deny"));

    drop(sup);
}
