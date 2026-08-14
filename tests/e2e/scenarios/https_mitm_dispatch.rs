use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::mpsc::{Sender, channel};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

use crate::audit::AuditDecision;
use crate::harness::TestWorld;

const RESPONSE: &str = "firma-e2e-https-upstream-ok\n";
const SANDBOX_PROBE: &str = r#"set -eu
if ls -- "$FIRMA_SIDECAR_CA_DIR" >/dev/null 2>&1; then
    echo firma-ca-direct-dir-listable
    exit 91
fi
echo firma-ca-direct-dir-hidden
if cat -- "$FIRMA_SIDECAR_CA_DIR/firma-ca.key" >/dev/null 2>&1; then
    echo firma-ca-direct-key-readable
    exit 92
fi
echo firma-ca-direct-key-hidden
if [ "$2" != - ]; then
    if cat -- "$2" >/dev/null 2>&1; then
        echo firma-ca-explicit-key-readable
        exit 93
    fi
    echo firma-ca-explicit-key-hidden
fi
test -r "$FIRMA_SIDECAR_CA_CERT_PATH"
echo firma-ca-cert-readable
exec curl --fail-with-body --silent --show-error --max-time 10 --data e2e-body "$1"
"#;

#[test]
fn generated_ca_trusts_mitm_and_dispatches_classified_https_request() {
    let checkout = std::env::current_dir().expect("test checkout path");
    assert!(
        !checkout.starts_with("/tmp"),
        "HTTPS CA isolation regression requires a checkout outside /tmp"
    );
    let external_state = tempfile::tempdir_in(checkout).expect("external state directory");
    let world = TestWorld::new_with_state_dir(external_state.path().join("state"));
    run_https_scenario(&world, Some(&external_state.path().join("explicit-ca")));
}

#[test]
fn generated_ca_isolated_when_runtime_state_is_under_tmp() {
    let world = TestWorld::new();
    run_https_scenario(&world, None);
}

#[test]
fn profile_alias_of_owned_ca_state_fails_closed_before_wrapped_command() {
    let checkout = std::env::current_dir().expect("test checkout path");
    let external_state = tempfile::tempdir_in(checkout).expect("external state directory");
    let world = TestWorld::new_with_state_dir(external_state.path().join("state"));
    let explicit_base = external_state.path().join("explicit-ca");
    enable_localhost_mitm(&world, Some(&explicit_base));
    append_layered_profile_alias(&world, external_state.path());

    let run = world.run_governed(
        "profile-ca-alias",
        "bash",
        ["-c", "echo wrapped-command-ran"],
    );

    assert!(
        !run.output.success(),
        "intersecting profile mount was accepted"
    );
    assert!(!run.output.stdout.contains("wrapped-command-ran"));
    assert!(
        run.output
            .stderr
            .contains("profile mount source intersects owned private CA material"),
        "unexpected fail-closed diagnostic:\n{}",
        run.output
    );
}

#[test]
fn ambient_non_owned_symlink_trust_file_remains_readable() {
    use std::os::unix::fs::symlink;

    let world = TestWorld::new();
    let real_ca = world.path("ambient-real-ca.crt");
    let advertised_ca = world.path("ambient-current-ca.crt");
    std::fs::write(&real_ca, "ambient-public-ca\n").expect("write ambient CA");
    symlink(&real_ca, &advertised_ca).expect("create ambient CA symlink");

    let run = world.run_governed_with_outer_env(
        "ambient-ca",
        &[("FIRMA_SIDECAR_CA_CERT_PATH", advertised_ca.as_os_str())],
        "bash",
        [
            "-c",
            "set -eu; test \"$FIRMA_SIDECAR_CA_CERT_PATH\" = \"$1\"; cat -- \"$FIRMA_SIDECAR_CA_CERT_PATH\"",
            "firma-ambient-ca",
            &advertised_ca.display().to_string(),
        ],
    );

    assert!(
        run.output.success(),
        "ambient CA symlink run failed:\n{}",
        run.output
    );
    assert!(run.output.stdout.ends_with("ambient-public-ca\n"));
    assert_eq!(run.output.stdout.matches("ambient-public-ca\n").count(), 1);
}

#[test]
fn enabled_mitm_without_intercept_hosts_launches_without_owned_ca_metadata() {
    let world = TestWorld::new();
    let path = world.config_path();
    let config = std::fs::read_to_string(&path).expect("read scaffolded config");
    let patched = config.replace(
        "[sidecar.interceptor.https_mitm]\nenabled = false",
        "[sidecar.interceptor.https_mitm]\nenabled = true\nintercept_hosts = []",
    );
    assert_ne!(patched, config, "expected generated HTTPS MITM section");
    std::fs::write(path, patched).expect("enable hostless HTTPS MITM");

    let run = world.run_governed(
        "hostless-mitm",
        "bash",
        [
            "-c",
            "set -eu; test -z \"${FIRMA_SIDECAR_CA_DIR+x}\"; test -z \"${FIRMA_SIDECAR_CA_CERT_PATH+x}\"; echo effectively-non-mitm-launched",
        ],
    );

    assert!(
        run.output.success(),
        "effectively non-MITM run failed:\n{}",
        run.output
    );
    assert!(
        run.output
            .stdout
            .ends_with("effectively-non-mitm-launched\n")
    );
    assert_eq!(
        run.output
            .stdout
            .matches("effectively-non-mitm-launched\n")
            .count(),
        1
    );
}

fn run_https_scenario(world: &TestWorld, explicit_base: Option<&std::path::Path>) {
    enable_localhost_mitm(world, explicit_base);
    let explicit_key = explicit_base.map(|path| path.with_extension("key"));
    let nonce = format!("https-{}", uuid::Uuid::new_v4().simple());
    let server = HttpsProbe::start(world, &nonce);
    let url = server.url();

    let run = world.run_governed_with_outer_env(
        &nonce,
        &[("SSL_CERT_FILE", server.ca_cert_path().as_os_str())],
        "bash",
        [
            "-c",
            SANDBOX_PROBE,
            "firma-https-e2e",
            &url,
            &explicit_key
                .as_ref()
                .map_or_else(|| "-".to_string(), |path| path.display().to_string()),
        ],
    );
    if !run.output.success() {
        eprintln!(
            "governed HTTPS request failed before upstream capture:\n{}",
            run.output
        );
    }
    let capture = server.finish();
    assert!(
        run.output.success(),
        "governed HTTPS request failed:\n{}",
        run.output
    );
    assert!(
        run.output.stdout.ends_with(RESPONSE) && run.output.stdout.matches(RESPONSE).count() == 1,
        "expected one governed HTTPS upstream response:\n{}",
        run.output
    );
    assert!(run.output.stdout.contains("firma-ca-direct-dir-hidden\n"));
    assert!(run.output.stdout.contains("firma-ca-direct-key-hidden\n"));
    assert_eq!(
        run.output.stdout.contains("firma-ca-explicit-key-hidden\n"),
        explicit_key.is_some()
    );
    assert!(run.output.stdout.contains("firma-ca-cert-readable\n"));
    assert!(!run.output.stdout.contains("listable"));
    assert!(!run.output.stdout.contains("key-readable"));

    assert_eq!(capture.method, "POST");
    assert_eq!(capture.path, format!("/{nonce}"));

    let event = run.audit_event();
    assert_eq!(event.action, "communication.internal.send");
    assert_eq!(
        event.resource,
        url.strip_prefix("https://").expect("HTTPS URL")
    );
    assert_eq!(event.decision, AuditDecision::Allow);
    assert_eq!(event.deny_reason, "");
    assert!(event.token_id.starts_with("ctok_"));
    assert_eq!(event.dispatch_status, 200);
}

fn enable_localhost_mitm(world: &TestWorld, explicit_base: Option<&std::path::Path>) {
    let path = world.config_path();
    let config = std::fs::read_to_string(&path).expect("read scaffolded config");
    let explicit_paths = explicit_base.map_or_else(String::new, |base| {
        format!(
            "\nca_cert_path = \"{}\"\nca_key_path = \"{}\"",
            base.with_extension("crt").display(),
            base.with_extension("key").display()
        )
    });
    let patched = config.replace(
        "[sidecar.interceptor.https_mitm]\nenabled = false",
        &format!(
            "[sidecar.interceptor.https_mitm]\nenabled = true{explicit_paths}\nintercept_hosts = [\"localhost\"]\nstrict_hosts = [\"localhost\"]"
        ),
    );
    assert_ne!(patched, config, "expected generated HTTPS MITM section");
    std::fs::write(path, patched).expect("enable scenario HTTPS MITM");
}

fn append_layered_profile_alias(world: &TestWorld, protected_ancestor: &std::path::Path) {
    let unrelated = world.path("unrelated-mount-source");
    let alias = world.workspace_path().join("layered-ca-alias");
    let nested_alias = alias.join("private");
    std::fs::create_dir_all(&unrelated).expect("create unrelated profile source");
    std::fs::create_dir_all(&alias).expect("create layered alias target");
    let path = world.config_path();
    let mut config = std::fs::read_to_string(&path).expect("read scaffolded config");
    for (source, target) in [
        (unrelated.as_path(), alias.as_path()),
        (protected_ancestor, nested_alias.as_path()),
    ] {
        writeln!(
            config,
            "\n[[run.profiles.generic.mounts]]\nsource = \"{}\"\ntarget = \"{}\"\nread_only = true",
            source.display(),
            target.display()
        )
        .expect("append layered profile mount");
    }
    std::fs::write(path, config).expect("write layered profile aliases");
}

#[derive(Debug)]
struct Capture {
    method: String,
    path: String,
}

struct HttpsProbe {
    address: SocketAddr,
    nonce: String,
    ca_cert_path: PathBuf,
    stop: Sender<()>,
    task: JoinHandle<Capture>,
}

impl HttpsProbe {
    fn start(world: &TestWorld, nonce: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind HTTPS probe");
        listener
            .set_nonblocking(true)
            .expect("make HTTPS probe accept bounded");
        let address = listener.local_addr().expect("HTTPS probe address");
        let (config, ca_pem) = tls_config();
        let ca_cert_path = world.path("upstream-ca.crt");
        std::fs::write(&ca_cert_path, ca_pem).expect("write HTTPS upstream CA");
        let (stop, stopped) = channel();
        let task = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(30);
            let (stream, _) = loop {
                match listener.accept() {
                    Ok(connection) => break connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            stopped.try_recv().is_err(),
                            "HTTPS probe stopped before request"
                        );
                        assert!(
                            Instant::now() < deadline,
                            "HTTPS probe received no connection"
                        );
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("accept HTTPS probe request: {error}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(15)))
                .expect("bound HTTPS probe reads");
            let connection = ServerConnection::new(std::sync::Arc::new(config))
                .expect("create HTTPS probe server connection");
            let mut stream = StreamOwned::new(connection, stream);
            let capture = read_request(&mut stream);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{RESPONSE}",
                RESPONSE.len()
            );
            stream
                .write_all(response.as_bytes())
                .expect("write HTTPS probe response");
            drop(stream);

            let duplicate_deadline = Instant::now() + Duration::from_millis(500);
            while Instant::now() < duplicate_deadline {
                match listener.accept() {
                    Ok(_) => panic!("HTTPS upstream received more than one connection"),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("check duplicate HTTPS request: {error}"),
                }
            }
            capture
        });
        Self {
            address,
            nonce: nonce.to_string(),
            ca_cert_path,
            stop,
            task,
        }
    }

    fn url(&self) -> String {
        format!(
            "https://localhost:{port}/{nonce}",
            port = self.address.port(),
            nonce = self.nonce
        )
    }

    fn ca_cert_path(&self) -> &std::path::Path {
        &self.ca_cert_path
    }

    fn finish(self) -> Capture {
        let _ = self.stop.send(());
        self.task.join().expect("HTTPS probe thread")
    }
}

fn tls_config() -> (ServerConfig, String) {
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().expect("generate HTTPS upstream CA key");
    let ca_cert = ca_params
        .self_signed(&ca_key)
        .expect("generate HTTPS upstream CA certificate");
    let leaf_key = KeyPair::generate().expect("generate HTTPS upstream leaf key");
    let leaf_params = CertificateParams::new(vec!["localhost".to_string()])
        .expect("build HTTPS upstream leaf parameters");
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &ca_cert, &ca_key)
        .expect("sign HTTPS upstream leaf certificate");
    let certificate = CertificateDer::from(leaf_cert.der().to_vec());
    let ca_certificate = CertificateDer::from(ca_cert.der().to_vec());
    let private_key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate, ca_certificate], private_key)
        .expect("build HTTPS probe TLS config");
    (config, ca_cert.pem())
}

fn read_request(stream: &mut impl Read) -> Capture {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 1024];
    while !bytes.windows(4).any(|window| window == b"\r\n\r\n") {
        let count = stream.read(&mut chunk).expect("read HTTPS request");
        assert_ne!(count, 0, "client closed before HTTPS headers");
        bytes.extend_from_slice(&chunk[..count]);
        assert!(bytes.len() < 32 * 1024, "oversized HTTPS test request");
    }
    let request = String::from_utf8(bytes).expect("ASCII HTTPS request");
    let mut parts = request
        .lines()
        .next()
        .expect("HTTPS request line")
        .split_whitespace();
    let capture = Capture {
        method: parts.next().expect("HTTPS method").to_string(),
        path: parts.next().expect("HTTPS path").to_string(),
    };
    assert_eq!(parts.next(), Some("HTTP/1.1"));
    capture
}
