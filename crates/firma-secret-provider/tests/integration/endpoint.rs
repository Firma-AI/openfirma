use std::str::FromStr;

use firma_secret_provider::endpoint::{
    EndpointInner, client::ClientEndpoint, error::EndpointParseError,
};
#[cfg(unix)]
use tokio::io;

#[test]
fn parse_tcp_address() {
    let ep = ClientEndpoint::from_str("tcp:127.0.0.1:1234").expect("parse");
    assert_eq!(
        ep.as_inner(),
        &EndpointInner::Tcp("127.0.0.1:1234".parse().unwrap())
    );
}

#[test]
fn parse_rejects_invalid_tcp_addr() {
    let err = ClientEndpoint::from_str("tcp:not-an-addr").expect_err("invalid");
    std::assert_matches!(err, EndpointParseError::InvalidTCP { addr, .. } if addr == "not-an-addr");
}

#[test]
fn parse_rejects_unknown_scheme() {
    let err = ClientEndpoint::from_str("vsock://3:1234").expect_err("unknown scheme");
    std::assert_matches!(err, EndpointParseError::Unrecognized(s) if s == "vsock://3:1234");
}

#[cfg(unix)]
fn set_mode(path: &std::path::Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = path.metadata()?.permissions();
    permissions.set_mode(mode);
    std::fs::set_permissions(path, permissions)?;

    Ok(())
}

#[cfg(unix)]
fn secure_temp_dir() -> io::Result<tempfile::TempDir> {
    let temp_dir = tempfile::TempDir::new()?;
    set_mode(temp_dir.path(), 0o700)?;
    Ok(temp_dir)
}

#[cfg(unix)]
fn secure_unix_socket() -> io::Result<(tempfile::TempDir, std::path::PathBuf)> {
    let temp_dir = secure_temp_dir()?;
    let socket_file = temp_dir.path().join("gateway.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&socket_file)?;
    set_mode(&socket_file, 0o600)?;
    Ok((temp_dir, socket_file))
}

#[cfg(unix)]
fn assert_wrong_permissions(path: &std::path::Path) {
    let path = path.display().to_string();
    let error = ClientEndpoint::from_str(&format!("unix:{path}"));
    std::assert_matches!(
        error,
        Err(EndpointParseError::WrongPermissions(actual)) if actual == path
    );
}

#[cfg(unix)]
#[test]
fn parse_unix_path() {
    let (_temp_dir, socket_file) = secure_unix_socket().expect("secure unix socket");

    let endpoint =
        ClientEndpoint::from_str(&format!("unix:{}", socket_file.display())).expect("parse");

    assert_eq!(endpoint.as_inner(), &EndpointInner::Unix(socket_file));
}

#[cfg(unix)]
#[test]
fn parse_rejects_world_accessible_unix_socket() {
    let (_temp_dir, socket_file) = secure_unix_socket().expect("secure unix socket");
    set_mode(&socket_file, 0o666).expect("set mode");

    assert_wrong_permissions(&socket_file);
}

#[cfg(unix)]
#[test]
fn parse_rejects_world_accessible_unix_socket_parent() {
    let (temp_dir, socket_file) = secure_unix_socket().expect("secure unix socket");
    set_mode(temp_dir.path(), 0o777).expect("set mode");

    assert_wrong_permissions(&socket_file);
}

#[cfg(unix)]
#[test]
fn parse_rejects_regular_file_at_unix_socket_path() {
    let temp_dir = secure_temp_dir().expect("secure temp dir");
    let socket_file = temp_dir.path().join("gateway.sock");
    std::fs::File::create_new(&socket_file).expect("file created");
    set_mode(&socket_file, 0o600).expect("set mode");

    let _error = ClientEndpoint::from_str(&format!("unix:{}", socket_file.display()))
        .expect_err("a regular file must not be accepted as a Unix socket");
}

#[cfg(unix)]
#[test]
fn parse_rejects_symlink_at_unix_socket_path() {
    let temp_dir = secure_temp_dir().expect("secure temp dir");
    let socket_file = temp_dir.path().join("actual.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&socket_file).expect("bind Unix socket");
    set_mode(&socket_file, 0o600).expect("set mode");

    let symlink = temp_dir.path().join("gateway.sock");
    std::os::unix::fs::symlink(&socket_file, &symlink).expect("create socket symlink");

    let _error = ClientEndpoint::from_str(&format!("unix:{}", symlink.display()))
        .expect_err("a symlink must not be accepted as a Unix socket");
}

#[cfg(unix)]
#[test]
fn parse_rejects_symlink_in_unix_socket_parent_path() {
    let temp_dir = secure_temp_dir().expect("secure temp dir");
    let socket_dir = temp_dir.path().join("actual");
    std::fs::create_dir(&socket_dir).expect("create socket directory");
    set_mode(&socket_dir, 0o700).expect("set mode");

    let socket_file = socket_dir.join("gateway.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&socket_file).expect("bind Unix socket");
    set_mode(&socket_file, 0o600).expect("set mode");

    let symlink = temp_dir.path().join("linked");
    std::os::unix::fs::symlink(&socket_dir, &symlink).expect("create directory symlink");
    let endpoint_path = symlink.join("gateway.sock");

    let _error = ClientEndpoint::from_str(&format!("unix:{}", endpoint_path.display()))
        .expect_err("a symlinked parent must not be accepted for a Unix socket");
}
