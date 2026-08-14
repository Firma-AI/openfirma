use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub(crate) struct Capture {
    pub(crate) method: String,
    pub(crate) path: String,
}

pub(crate) struct Upstream {
    address: SocketAddr,
    nonce: String,
    task: JoinHandle<Capture>,
}

impl Upstream {
    pub(crate) fn start(nonce: &str, body: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind upstream");
        listener
            .set_nonblocking(true)
            .expect("make upstream accept bounded");
        let address = listener.local_addr().expect("upstream address");
        let task = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(30);
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(connection) => break connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "upstream received no request");
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("accept upstream request: {error}"),
                }
            };
            stream
                .set_nonblocking(false)
                .expect("restore blocking stream reads");
            stream
                .set_read_timeout(Some(Duration::from_secs(15)))
                .expect("set upstream read timeout");
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
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .expect("write response");
            capture
        });
        Self {
            address,
            nonce: nonce.to_string(),
            task,
        }
    }

    pub(crate) fn url(&self) -> String {
        format!("http://{}/{nonce}", self.address, nonce = self.nonce)
    }

    pub(crate) fn finish(self) -> Capture {
        self.task.join().expect("upstream thread")
    }
}
