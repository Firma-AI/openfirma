//! End-to-end: spawn an Authority fixture that reads the generated config,
//! binds its configured dynamic address, and emits the startup contract.

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
    use std::os::unix::fs::PermissionsExt as _;
    let tmp = tempfile::tempdir().expect("tempdir");
    let fake = tmp.path().join("fake-firma.sh");
    let fixture_bin = tmp.path().join("authority-fixture-bin");
    std::os::unix::fs::symlink(
        std::env::current_exe().expect("test executable"),
        &fixture_bin,
    )
    .expect("link fixture test executable");
    std::fs::write(
        &fake,
        "#!/usr/bin/env bash\n\
         export FIRMA_TEST_AUTHORITY_CONFIG=\"$3\"\n\
         exec \"$(dirname \"$0\")/authority-fixture-bin\" \
           --exact authority_autostart_marker::authority_fixture --ignored --nocapture\n",
    )
    .unwrap();
    let mut p = std::fs::metadata(&fake).unwrap().permissions();
    p.set_mode(0o755);
    std::fs::set_permissions(&fake, p).unwrap();

    let sandbox_id = firma_run::identity::SandboxId::generate();
    let marker = tmp.path().join("marker/authority");
    let sup = AuthoritySupervisor::spawn(SpawnRequest {
        sandbox_id: &sandbox_id,
        agent_id: super::helper::agent_id(),
        session_id: "sess",
        marker_dir: marker.clone(),
        profile_name: "developer",
        firma_exe: fake,
        startup_timeout: Duration::from_secs(5),
        user_config_path: None,
    })
    .expect("spawn ok");

    assert!(marker.join("authority.toml").is_file());
    assert!(marker.join("authority.pid").is_file());
    assert!(marker.join("metadata.toml").is_file());
    assert!(marker.join("policy_dir/developer.cedar").is_file());
    assert!(marker.join("keys/authority.key").is_file());
    assert!(marker.join("keys/authority.pub").is_file());

    let config = std::fs::read_to_string(marker.join("authority.toml")).unwrap();
    assert!(
        config.contains("listen_addr = \"[::1]:0\""),
        "got: {config}"
    );

    let meta = std::fs::read_to_string(marker.join("metadata.toml")).unwrap();
    assert!(
        meta.contains(&format!("sandbox_id = \"{sandbox_id}\"")),
        "got: {meta}"
    );
    assert!(meta.contains("profile = \"developer\""));
    let endpoint = sup.url().strip_prefix("http://").unwrap().to_string();
    assert_ne!(endpoint, "[::1]:0");
    assert!(meta.contains(&format!("listen_addr = \"{endpoint}\"")));
    let address: std::net::SocketAddr = endpoint.parse().expect("parse fixture endpoint");
    assert_ne!(address.port(), 0);
    std::net::TcpStream::connect_timeout(&address, Duration::from_secs(1))
        .expect("fixture is reachable at the published endpoint");

    let cedar = std::fs::read_to_string(marker.join("policy_dir/developer.cedar")).unwrap();
    assert!(cedar.contains("Local autostart profile for `firma run`."));
    assert!(cedar.contains("permit(principal, action, resource)"));

    drop(sup);
}

#[cfg(unix)]
#[test]
#[ignore = "spawned as a process-lifecycle fixture"]
fn authority_fixture() {
    let config_path = std::env::var_os("FIRMA_TEST_AUTHORITY_CONFIG")
        .map(std::path::PathBuf::from)
        .expect("fixture config path");
    let config_text = std::fs::read_to_string(config_path).expect("read fixture config");
    let config: toml::Value = toml::from_str(&config_text).expect("parse fixture config");
    let configured = config["authority"]["listen_addr"]
        .as_str()
        .expect("configured listen address");
    let listener = std::net::TcpListener::bind(configured).expect("bind configured address");
    let effective = listener.local_addr().expect("effective listen address");
    eprintln!("firma_authority: config loaded listen_addr=\"{configured}\"");
    eprintln!("firma_authority: listening addr=\"{effective}\"");
    eprintln!("firma_authority: authority ready");
    loop {
        std::thread::sleep(Duration::from_mins(1));
    }
}

#[cfg(unix)]
#[test]
fn pidfile_publication_failure_reaps_started_authority() {
    use std::os::unix::fs::PermissionsExt as _;

    let tmp = tempfile::tempdir().expect("tempdir");
    let marker = tmp.path().join("marker/authority");
    let observed_pid = tmp.path().join("observed.pid");
    let fake = tmp.path().join("fake-firma.sh");
    std::fs::write(
        &fake,
        format!(
            "#!/usr/bin/env bash\n\
             mkdir '{}'/authority.pid\n\
             echo $$ > '{}'\n\
             echo 'firma_authority: listening addr=\"[::1]:54321\"' >&2\n\
             echo 'firma_authority: authority ready' >&2\n\
             exec sleep 60\n",
            marker.display(),
            observed_pid.display()
        ),
    )
    .expect("write fake");
    let mut permissions = std::fs::metadata(&fake).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&fake, permissions).unwrap();
    let sandbox_id = firma_run::identity::SandboxId::generate();

    let result = AuthoritySupervisor::spawn(SpawnRequest {
        sandbox_id: &sandbox_id,
        agent_id: super::helper::agent_id(),
        session_id: "sess",
        marker_dir: marker,
        profile_name: "developer",
        firma_exe: fake,
        startup_timeout: Duration::from_secs(2),
        user_config_path: None,
    });

    assert!(result.is_err(), "pidfile publication must fail");
    let pid: i32 = std::fs::read_to_string(observed_pid)
        .expect("fixture recorded pid")
        .trim()
        .parse()
        .expect("parse pid");
    assert_eq!(
        nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None),
        Err(nix::errno::Errno::ESRCH),
        "startup owner must synchronously kill and reap the child"
    );
}
