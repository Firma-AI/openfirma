use std::io::{BufRead, BufReader, Write};
use std::process::{ChildStdin, ChildStdout, Command};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use firma_test_helpers::process_fixture;
use serde::{Deserialize, Serialize};

const PROTOCOL_PREFIX: &str = "FIRMA_E2E_HTTP ";

#[derive(Deserialize, Serialize)]
struct LiveHttpRequest {
    nonce: String,
    url: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum LiveHttpEvent {
    Ready {
        process_id: u32,
        mount_namespace: String,
    },
    Attempt {
        nonce: String,
    },
    Response {
        nonce: String,
        status: u16,
        body: Vec<u8>,
    },
    Error {
        nonce: String,
        message: String,
    },
}

/// Identity reported by the request fixture after it starts inside the sandbox.
pub(crate) struct LiveHttpReady {
    pub(crate) process_id: u32,
    pub(crate) mount_namespace: String,
}

/// The HTTP response returned to a request made inside a live governed sandbox.
pub(crate) struct LiveHttpResponse {
    /// HTTP status returned by the Sidecar or upstream destination.
    pub(crate) status: u16,
    /// Response body returned by the Sidecar or upstream destination.
    pub(crate) body: Vec<u8>,
}

/// A piped connection to the Rust request fixture running inside the sandbox.
pub(crate) struct LiveHttpClient {
    stdin: Option<ChildStdin>,
    events: Receiver<Result<LiveHttpEvent, String>>,
    stdout: Arc<Mutex<String>>,
}

impl LiveHttpClient {
    /// Starts consuming fixture events from `stdout` on a detached reader thread.
    pub(crate) fn new(stdin: ChildStdin, stdout: ChildStdout) -> Self {
        let (events, capture) = start_stdout_reader(stdout);
        Self {
            stdin: Some(stdin),
            events,
            stdout: capture,
        }
    }

    /// Waits for the fixture's first readiness event.
    pub(crate) fn wait_until_ready(&self, timeout: Duration) -> Result<LiveHttpReady, String> {
        match self.receive_event(timeout)? {
            LiveHttpEvent::Ready {
                process_id,
                mount_namespace,
            } => Ok(LiveHttpReady {
                process_id,
                mount_namespace,
            }),
            event => Err(format!("fixture did not send readiness first: {event:?}")),
        }
    }

    /// Sends one GET request and returns the response received inside the sandbox.
    pub(crate) fn request(&mut self, nonce: &str, url: &str) -> Result<LiveHttpResponse, String> {
        let stdin = self.stdin.as_mut().ok_or("live HTTP input is closed")?;
        serde_json::to_writer(
            &mut *stdin,
            &LiveHttpRequest {
                nonce: nonce.to_string(),
                url: url.to_string(),
            },
        )
        .map_err(|error| format!("serialize live HTTP request: {error}"))?;
        writeln!(stdin).map_err(|error| format!("terminate live HTTP request: {error}"))?;
        stdin
            .flush()
            .map_err(|error| format!("flush live HTTP request: {error}"))?;

        match self.receive_event(Duration::from_secs(5))? {
            LiveHttpEvent::Attempt {
                nonce: attempted_nonce,
            } if attempted_nonce == nonce => {}
            event => {
                return Err(format!(
                    "expected request attempt for {nonce}, got {event:?}"
                ));
            }
        }
        match self.receive_event(Duration::from_secs(10))? {
            LiveHttpEvent::Response {
                nonce: response_nonce,
                status,
                body,
            } if response_nonce == nonce => Ok(LiveHttpResponse { status, body }),
            LiveHttpEvent::Error {
                nonce: response_nonce,
                message,
            } if response_nonce == nonce => Err(format!("request {nonce} failed: {message}")),
            event => Err(format!(
                "expected request response for {nonce}, got {event:?}"
            )),
        }
    }

    /// Closes the request stream so the fixture can finish cleanly.
    pub(crate) fn close_input(&mut self) {
        self.stdin.take();
    }

    /// Returns the stdout observed so far without waiting for the reader thread to finish.
    pub(crate) fn stdout(&self) -> String {
        self.stdout
            .lock()
            .expect("live HTTP stdout capture")
            .clone()
    }

    fn receive_event(&self, timeout: Duration) -> Result<LiveHttpEvent, String> {
        match self.events.recv_timeout(timeout) {
            Ok(Ok(event)) => Ok(event),
            Ok(Err(error)) => Err(format!("invalid live HTTP protocol: {error}")),
            Err(RecvTimeoutError::Timeout) => {
                Err("timed out waiting for live HTTP event".to_string())
            }
            Err(RecvTimeoutError::Disconnected) => {
                Err("live HTTP protocol closed unexpectedly".to_string())
            }
        }
    }
}

/// Returns the process-fixture command used as the wrapped sandbox executable.
pub(crate) fn command() -> Command {
    let mut command = live_http_client_fixture();
    command.arg("--nocapture");
    command
}

process_fixture! {
    fn live_http_client_fixture() {
        let proxy = std::env::var("HTTP_PROXY").expect("live HTTP proxy URL");
        let client = reqwest::blocking::Client::builder()
            .use_preconfigured_tls(build_tls_config())
            .proxy(reqwest::Proxy::all(proxy).expect("configure live HTTP proxy"))
            .timeout(Duration::from_secs(3))
            .build()
            .expect("build live HTTP client");
        let stdin = std::io::stdin();
        let stdout = std::io::stdout();
        let mut stdout = stdout.lock();
        write_event(
            &mut stdout,
            &LiveHttpEvent::Ready {
                process_id: std::process::id(),
                mount_namespace: std::fs::read_link("/proc/self/ns/mnt")
                    .expect("read fixture mount namespace")
                    .to_string_lossy()
                    .into_owned(),
            },
        );

        for line in stdin.lock().lines() {
            let line = line.expect("read live HTTP request");
            let request: LiveHttpRequest =
                serde_json::from_str(&line).expect("deserialize live HTTP request");
            write_event(
                &mut stdout,
                &LiveHttpEvent::Attempt {
                    nonce: request.nonce.clone(),
                },
            );
            let event = match client.get(&request.url).send() {
                Ok(response) => {
                    let status = response.status().as_u16();
                    match response.bytes() {
                        Ok(body) => LiveHttpEvent::Response {
                            nonce: request.nonce,
                            status,
                            body: body.to_vec(),
                        },
                        Err(error) => LiveHttpEvent::Error {
                            nonce: request.nonce,
                            message: format!("read HTTP response body: {error}"),
                        },
                    }
                }
                Err(error) => LiveHttpEvent::Error {
                    nonce: request.nonce,
                    message: format!("send HTTP request: {error}"),
                },
            };
            write_event(&mut stdout, &event);
        }
    }
}

fn build_tls_config() -> rustls::ClientConfig {
    use rustls_platform_verifier::BuilderVerifierExt as _;

    rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("configure live HTTP TLS protocol versions")
        .with_platform_verifier()
        .expect("configure live HTTP platform verifier")
        .with_no_client_auth()
}

fn write_event(writer: &mut impl Write, event: &LiveHttpEvent) {
    write!(writer, "{PROTOCOL_PREFIX}").expect("write live HTTP protocol prefix");
    serde_json::to_writer(&mut *writer, event).expect("serialize live HTTP event");
    writeln!(writer).expect("terminate live HTTP event");
    writer.flush().expect("flush live HTTP event");
}

fn start_stdout_reader(
    stdout: ChildStdout,
) -> (Receiver<Result<LiveHttpEvent, String>>, Arc<Mutex<String>>) {
    let (sender, receiver) = channel();
    let capture = Arc::new(Mutex::new(String::new()));
    let reader_capture = Arc::clone(&capture);
    let _reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            match line {
                Ok(line) => {
                    let mut capture = reader_capture.lock().expect("live HTTP stdout capture");
                    capture.push_str(&line);
                    capture.push('\n');
                    drop(capture);
                    if let Some((_, encoded)) = line.split_once(PROTOCOL_PREFIX) {
                        let event = serde_json::from_str(encoded).map_err(|error| {
                            format!("deserialize live HTTP event {encoded:?}: {error}")
                        });
                        let _ = sender.send(event);
                    }
                }
                Err(error) => {
                    let _ = sender.send(Err(format!("read live governed stdout: {error}")));
                    break;
                }
            }
        }
    });
    (receiver, capture)
}
