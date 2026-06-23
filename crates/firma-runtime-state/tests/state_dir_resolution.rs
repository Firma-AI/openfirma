//! State directory resolution chain.

use std::path::PathBuf;

use firma_runtime_state::state_dir::resolve_state_dir_from;

#[test]
fn flag_wins() {
    let path = PathBuf::from("/explicit");
    let got = resolve_state_dir_from(Some(path.clone()), None, None, None, None).expect("resolve");
    assert_eq!(got, path);
}

#[test]
fn env_used_when_no_flag() {
    let got = resolve_state_dir_from(None, Some("/from-env".to_string()), None, None, None)
        .expect("resolve");
    assert_eq!(got, PathBuf::from("/from-env"));
}

#[cfg(unix)]
#[test]
fn unix_falls_back_to_xdg_runtime_dir() {
    let got = resolve_state_dir_from(None, None, Some("/run/user/1000".to_string()), None, None)
        .expect("resolve");
    assert_eq!(got, PathBuf::from("/run/user/1000/firma"));
}
