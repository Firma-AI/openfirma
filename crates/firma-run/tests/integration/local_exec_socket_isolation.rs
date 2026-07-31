//! The sidecar's local-exec governance socket (`decide` and the operator
//! `decide_management` approve/revoke commands share one Unix domain socket)
//! must be unreachable from inside the sandbox. The sandboxed agent runs as
//! the sidecar's UID and reaches sibling sockets through the root bind mount,
//! so a reachable management endpoint would let the agent self-approve pending
//! HITL tokens — the management token it can read from the inherited env or a
//! same-UID file is not a sufficient barrier. firma-run masks the socket from
//! the agent's mount namespace instead; these tests pin the mask-arg builder.

use std::path::Path;

use firma_run::backend::local_exec_socket_mask_args;

#[test]
fn mask_overlays_devnull_on_absolute_socket() {
    let args = local_exec_socket_mask_args(Some(Path::new("/run/firma/sidecar-tools.sock")));
    let rendered: Vec<String> = args
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        rendered,
        vec![
            "--ro-bind".to_string(),
            "/dev/null".to_string(),
            "/run/firma/sidecar-tools.sock".to_string(),
        ],
        "the local-exec socket must be shadowed by /dev/null inside the sandbox"
    );
}

#[test]
fn mask_emits_nothing_when_governance_absent() {
    assert!(
        local_exec_socket_mask_args(None).is_empty(),
        "no socket to mask when local-exec governance is not configured"
    );
}

#[test]
fn mask_rejects_relative_socket_paths() {
    assert!(
        local_exec_socket_mask_args(Some(Path::new("relative.sock"))).is_empty(),
        "relative paths would not target the real socket inside the sandbox root"
    );
}
