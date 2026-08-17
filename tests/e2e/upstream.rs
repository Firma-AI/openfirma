use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::mpsc::{Sender, channel};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// The request-line fields captured by an [`HttpProbe`].
#[derive(Debug)]
pub(crate) struct Capture {
    /// The HTTP method received by the probe.
    pub(crate) method: String,
    /// The request target received by the probe.
    pub(crate) path: String,
}

/// The single-connection behavior expected from an [`HttpProbe`].
pub(crate) enum ProbeBehavior {
    /// Capture one request and return a successful response with this body.
    Respond(&'static str),
    /// Capture one request and close its connection without sending an HTTP response.
    CloseWithoutResponse,
    /// Fail if any connection arrives before the probe is finished.
    MustNotConnect,
}

/// A single-request HTTP/1.1 probe for dispatch and network-isolation scenarios.
///
/// The probe deliberately exposes connection-level behavior that a normal HTTP mock does not: it
/// can close without responding and can assert that no TCP connection occurred. Call [`Self::finish`]
/// after the client command to stop the listener and join its thread.
pub(crate) struct HttpProbe {
    address: SocketAddr,
    nonce: String,
    stop: Sender<()>,
    task: JoinHandle<Option<Capture>>,
}

impl HttpProbe {
    /// Starts a loopback probe whose request path is `/{nonce}`.
    ///
    /// Request acceptance has a 30-second deadline and each header read has a 15-second timeout.
    /// The probe accepts at most one connection and fails on malformed or oversized requests.
    pub(crate) fn start(nonce: &str, behavior: ProbeBehavior) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind HTTP probe");
        listener
            .set_nonblocking(true)
            .expect("make HTTP probe accept bounded");
        let address = listener.local_addr().expect("HTTP probe address");
        let (stop, stopped) = channel();
        let task = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(30);
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(connection) => break connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if matches!(behavior, ProbeBehavior::MustNotConnect)
                            && stopped.try_recv().is_ok()
                        {
                            return None;
                        }
                        assert!(Instant::now() < deadline, "HTTP probe received no request");
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("accept HTTP probe request: {error}"),
                }
            };
            assert!(
                !matches!(behavior, ProbeBehavior::MustNotConnect),
                "request reached a must-not-connect HTTP probe"
            );
            stream
                .set_nonblocking(false)
                .expect("restore blocking HTTP probe reads");
            stream
                .set_read_timeout(Some(Duration::from_secs(15)))
                .expect("set HTTP probe read timeout");
            let capture = read_request(&mut stream);
            match behavior {
                ProbeBehavior::Respond(body) => {
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    stream
                        .write_all(response.as_bytes())
                        .expect("write HTTP probe response");
                }
                ProbeBehavior::CloseWithoutResponse => drop(stream),
                ProbeBehavior::MustNotConnect => unreachable!(),
            }
            Some(capture)
        });
        Self {
            address,
            nonce: nonce.to_string(),
            stop,
            task,
        }
    }

    /// Returns the probe URL using its loopback IP address as the host.
    pub(crate) fn url(&self) -> String {
        format!("http://{}/{nonce}", self.address, nonce = self.nonce)
    }

    /// Returns the probe URL with `host` in the authority while retaining the bound loopback port.
    ///
    /// The caller is responsible for resolving `host` to the probe's loopback address.
    pub(crate) fn url_for_host(&self, host: &str) -> String {
        format!(
            "http://{host}:{port}/{nonce}",
            port = self.address.port(),
            nonce = self.nonce
        )
    }

    /// Stops a negative probe, joins the listener thread, and returns any captured request.
    ///
    /// Positive behaviors wait for their expected connection or the acceptance deadline. A
    /// [`ProbeBehavior::MustNotConnect`] probe returns `None` once no connection has occurred before
    /// this method is called.
    pub(crate) fn finish(self) -> Option<Capture> {
        let _ = self.stop.send(());
        self.task.join().expect("HTTP probe thread")
    }
}

fn read_request(stream: &mut std::net::TcpStream) -> Capture {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 1024];
    while !bytes.windows(4).any(|window| window == b"\r\n\r\n") {
        let count = stream.read(&mut chunk).expect("read HTTP request");
        assert_ne!(count, 0, "client closed before HTTP headers");
        bytes.extend_from_slice(&chunk[..count]);
        assert!(bytes.len() < 32 * 1024, "oversized test request");
    }
    let request = String::from_utf8(bytes).expect("ASCII HTTP request");
    let request_line = request.lines().next().expect("HTTP request line");
    let mut parts = request_line.split_whitespace();
    let capture = Capture {
        method: parts.next().expect("HTTP method").to_string(),
        path: parts.next().expect("HTTP path").to_string(),
    };
    assert_eq!(parts.next(), Some("HTTP/1.1"));
    capture
}
